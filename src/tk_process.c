/*
 * tk_process.c - locate the process that maps a given image and verify it.
 *
 * The image name is a parameter: the framework can be pointed at any
 * Windows-on-Wine game by targets that have checked, in kernel code, that
 * the patterns and decoders they carry belong to that image.
 *
 * Everything here runs on the watcher workqueue (sleepable).  Two ordering
 * constraints shape the code:
 *
 *   1. access_process_vm() acquires the target's mmap_lock itself, so the
 *      PE headers can only be read AFTER the VMA walk has released it.
 *   2. mmput() may sleep, so while the task list is being walked under RCU
 *      the code uses mmap_read_trylock() and mmput_async().
 *
 * Hence the two phases below: collect candidates under RCU, then verify them
 * with the lock dropped.
 *
 * Candidates hold mm_users while they are being examined (the VMA walk and
 * the remote reads need a live address space).  The winner is handed out
 * holding only mm_count: the trap handler uses the mm purely as an identity
 * to compare against, and pinning mm_users would keep the game's whole
 * address space alive after it exits.
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/string.h>

#include "tk_internal.h"

/*
 * The game runs under Wine, so the process's real executable is Wine's own
 * loader (wine64-preloader, wine-preloader, wine64 or wine, depending on the
 * build and on Proton's version).  Checking that is a few pointer loads,
 * where the VMA walk below costs time proportional to the size of every
 * address space on the machine - a browser alone has tens of thousands of
 * mappings - all of it under RCU with no chance to reschedule.
 */
static const char tk_wine_exe_prefix[] = "wine";
#define TK_WINE_EXE_PREFIX_LEN (sizeof(tk_wine_exe_prefix) - 1)

/* Several Wine processes can map the image; only one is the real game, so
 * collect a few and let the PE check pick.  A handful is always enough. */
#define TK_MAX_CANDIDATES 8

/* PE/COFF header offsets we rely on, relative to the image base. */
#define TK_PE_OFFSET_LFANEW 0x3c /* MZ header field holding the PE header offset */
#define TK_PE_OFFSET_SIZE_OF_IMAGE 0x50 /* from the PE signature, in the optional header */

/* Sanity bounds for the two header fields we trust. */
#define TK_PE_LFANEW_MIN 0x40
#define TK_PE_LFANEW_MAX 0x400
#define TK_PE_IMAGE_SIZE_MIN 0x1000
#define TK_PE_IMAGE_SIZE_MAX 0x20000000

#define TK_MZ_SIGNATURE 0x5a4d     /* "MZ" */
#define TK_PE_SIGNATURE 0x00004550 /* "PE\0\0" */

/* One process that has the image mapped; refs on task and mm are held. */
struct tk_candidate
{
    struct task_struct* task;
    struct mm_struct* mm;
    unsigned long image_base;
};

bool tk_task_is_alive(struct task_struct* task)
{
    return task && READ_ONCE(task->exit_state) == 0 && READ_ONCE(task->mm) != NULL;
}

/*
 * Does this VMA map a file whose basename is the target's image name?
 *
 * Context: caller holds RCU and the mm's mmap_lock, which is what makes the
 * lockless d_name read safe enough for a name comparison: the length is
 * checked first and the compare is bounded, so a concurrent rename can only
 * cause a missed match, never an over-read.
 */
static bool vma_maps_target_image(struct vm_area_struct* vma, const char* image_name, size_t name_len)
{
    const struct dentry* dentry;

    if (!vma->vm_file)
    {
        return false;
    }
    dentry = file_dentry(vma->vm_file);
    if (dentry->d_name.len != name_len)
    {
        return false;
    }
    return strncasecmp(dentry->d_name.name, image_name, name_len) == 0;
}

/*
 * Is this mm's executable a Wine loader?
 *
 * Context: caller holds RCU and an mm_users reference.  exe_file is
 * RCU-protected; the name read is lockless for the same reason as in
 * vma_maps_target_image(), so a racing change can only cause a missed or a
 * spurious candidate, and every candidate is still fully verified later.
 */
static bool mm_runs_wine(struct mm_struct* mm)
{
    const struct file* exe = rcu_dereference(mm->exe_file);
    const struct dentry* dentry;

    if (!exe)
    {
        return false;
    }
    dentry = exe->f_path.dentry;
    return dentry->d_name.len >= TK_WINE_EXE_PREFIX_LEN &&
           strncmp(dentry->d_name.name, tk_wine_exe_prefix, TK_WINE_EXE_PREFIX_LEN) == 0;
}

/*
 * Find the load address of the image in this mm, or 0 if it is absent.
 *
 * The mapping at file offset 0 is the image start.  If no such mapping is
 * present (a partially torn-down or unusually laid out process), fall back to
 * the lowest image mapping.
 *
 * Context: caller holds the mm's mmap_lock for reading.
 */
static unsigned long find_image_base(struct mm_struct* mm, const char* image_name, size_t name_len)
{
    VMA_ITERATOR(vmi, mm, 0);
    struct vm_area_struct* vma;
    unsigned long lowest = 0;

    for_each_vma(vmi, vma)
    {
        if (!vma_maps_target_image(vma, image_name, name_len))
        {
            continue;
        }
        if (vma->vm_pgoff == 0)
        {
            return vma->vm_start;
        }
        if (!lowest || vma->vm_start < lowest)
        {
            lowest = vma->vm_start;
        }
    }
    return lowest;
}

/*
 * Append one clipped range.  Returns 1 if it had to be dropped because the
 * array is full, so the caller can report the total once instead of once per
 * mapping.
 */
static unsigned int record_range(struct tk_address_range* ranges, unsigned int* count, unsigned long start,
                                 unsigned long end)
{
    if (start >= end)
    {
        return 0;
    }
    if (*count >= TK_MAX_RANGES)
    {
        return 1;
    }
    ranges[*count].start = start;
    ranges[*count].end = end;
    (*count)++;
    return 0;
}

/*
 * Split the image's mappings into the two sets the scanner works on, clipped
 * to the image: executable ones (where the patch sites live) and readable
 * non-executable ones (where a target's string literals live).  Anything
 * neither readable nor executable is of no use to either scan.
 *
 * Context: caller holds the mm's mmap_lock for reading.
 */
static void collect_ranges(struct mm_struct* mm, struct tk_game_ref* game)
{
    unsigned long image_end = game->image_base + game->image_size;
    VMA_ITERATOR(vmi, mm, game->image_base);
    struct vm_area_struct* vma;
    unsigned int dropped = 0;

    game->exec_range_count = 0;
    game->data_range_count = 0;

    for_each_vma_range(vmi, vma, image_end)
    {
        unsigned long start = max(vma->vm_start, game->image_base);
        unsigned long end = min(vma->vm_end, image_end);

        if (vma->vm_flags & VM_EXEC)
        {
            dropped += record_range(game->exec_ranges, &game->exec_range_count, start, end);
        }
        else if (vma->vm_flags & VM_READ)
        {
            dropped += record_range(game->data_ranges, &game->data_range_count, start, end);
        }
    }

    if (dropped)
    {
        pr_warn("trapkit: %u image mapping(s) past the %d we track per kind will not be scanned\n", dropped,
                TK_MAX_RANGES);
    }
}

/*
 * Confirm that image_base really is a PE image and return its SizeOfImage.
 *
 * Context: sleepable, mmap_lock NOT held (tk_read_remote takes it).
 * Returns 0 if the headers do not check out.
 */
static unsigned long read_pe_image_size(struct task_struct* task, unsigned long image_base)
{
    u16 mz_signature;
    u32 pe_header_offset;
    u32 pe_signature;
    u32 image_size;

    if (tk_read_remote_exact(task, image_base, &mz_signature, sizeof(mz_signature)) ||
        mz_signature != TK_MZ_SIGNATURE)
    {
        return 0;
    }
    if (tk_read_remote_exact(task, image_base + TK_PE_OFFSET_LFANEW, &pe_header_offset,
                              sizeof(pe_header_offset)) ||
        pe_header_offset < TK_PE_LFANEW_MIN || pe_header_offset > TK_PE_LFANEW_MAX)
    {
        return 0;
    }
    if (tk_read_remote_exact(task, image_base + pe_header_offset, &pe_signature, sizeof(pe_signature)) ||
        pe_signature != TK_PE_SIGNATURE)
    {
        return 0;
    }
    if (tk_read_remote_exact(task, image_base + pe_header_offset + TK_PE_OFFSET_SIZE_OF_IMAGE, &image_size,
                              sizeof(image_size)) ||
        image_size < TK_PE_IMAGE_SIZE_MIN || image_size > TK_PE_IMAGE_SIZE_MAX)
    {
        return 0;
    }
    return image_size;
}

/*
 * Phase one: walk the task list and note every process with the image mapped.
 *
 * Context: sleepable, but the walk itself is under RCU, so it may only use
 * non-sleeping primitives - hence mmap_read_trylock() and mmput_async().
 * A process whose mmap_lock is busy right now is simply skipped; the poll
 * runs again shortly.
 *
 * Returns the number of candidates collected, each holding task + mm refs.
 */
static unsigned int collect_candidates(struct tk_candidate* candidates, unsigned int max_candidates,
                                       const char* image_name, size_t name_len)
{
    struct task_struct* task;
    unsigned int count = 0;

    rcu_read_lock();
    for_each_process(task)
    {
        struct mm_struct* mm;
        unsigned long image_base;

        if (count >= max_candidates)
        {
            break;
        }
        if (task->flags & PF_KTHREAD)
        {
            continue;
        }

        mm = get_task_mm(task);
        if (!mm)
        {
            continue; /* kernel thread or already exited */
        }
        if (!mm_runs_wine(mm))
        {
            mmput_async(mm);
            continue; /* not a Wine process: skip its VMAs entirely */
        }
        if (!mmap_read_trylock(mm))
        {
            mmput_async(mm);
            continue;
        }
        image_base = find_image_base(mm, image_name, name_len);
        mmap_read_unlock(mm);

        if (!image_base)
        {
            mmput_async(mm);
            continue;
        }

        get_task_struct(task);
        candidates[count].task = task;
        candidates[count].mm = mm;
        candidates[count].image_base = image_base;
        count++;
    }
    rcu_read_unlock();

    return count;
}

static void release_candidate(struct tk_candidate* candidate)
{
    mmput(candidate->mm);
    put_task_struct(candidate->task);
}

int tk_find_game(struct tk_game_ref* out, const char* image_name)
{
    struct tk_candidate candidates[TK_MAX_CANDIDATES];
    size_t name_len = strlen(image_name);
    unsigned int count;
    unsigned int i;
    int winner = -1;

    memset(out, 0, sizeof(*out));

    count = collect_candidates(candidates, TK_MAX_CANDIDATES, image_name, name_len);

    /* Phase two, with no locks held: confirm the PE headers and take the
     * first candidate that both verifies and has executable code mapped. */
    for (i = 0; i < count; i++)
    {
        unsigned long image_size;

        if (winner >= 0)
        {
            continue; /* already chosen; the loop only releases the rest */
        }

        image_size = read_pe_image_size(candidates[i].task, candidates[i].image_base);
        if (!image_size)
        {
            continue;
        }

        out->task = candidates[i].task;
        out->mm = candidates[i].mm;
        out->pid = task_pid_nr(candidates[i].task);
        out->image_base = candidates[i].image_base;
        out->image_size = image_size;

        mmap_read_lock(candidates[i].mm);
        collect_ranges(candidates[i].mm, out);
        mmap_read_unlock(candidates[i].mm);

        if (out->exec_range_count == 0)
        {
            memset(out, 0, sizeof(*out));
            continue;
        }
        winner = (int)i;
    }

    for (i = 0; i < count; i++)
    {
        if ((int)i != winner)
        {
            release_candidate(&candidates[i]);
        }
    }

    if (winner < 0)
    {
        return -ESRCH;
    }

    /* Trade the winner's mm_users for mm_count: from here on the mm is only
     * an identity for the trap handler to compare against.  mmput() may run
     * exit_mmap() if the game exited meanwhile; we are sleepable here. */
    mmgrab(out->mm);
    mmput(out->mm);
    return 0;
}

void tk_release_game(struct tk_game_ref* game)
{
    if (game->mm)
    {
        mmdrop(game->mm);
        game->mm = NULL;
    }
    if (game->task)
    {
        put_task_struct(game->task);
        game->task = NULL;
    }
}
