/*
 * tk_internal.h - framework-private state and cross-unit declarations.
 *
 * Nothing here is part of the public API; the application module must include
 * tk.h only.
 */
#ifndef TK_INTERNAL_H
#define TK_INTERNAL_H

#include <asm/ptrace.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/perf_event.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "tk.h"

struct mm_struct;
struct task_struct;

/*
 * One patch site: where it lives, how it reacts to a hit, and how often it
 * has fired.  What a hit does is the site's tk_action; everything
 * game-specific about it was decided while the site was being resolved,
 * before the breakpoint could exist.
 */
struct tk_site
{
    struct tk_target* target; /* back pointer, for the target's per-target mm filter */
    unsigned int index;        /* index in target->sites[] */
    const struct tk_site_desc* desc;

    bool found;   /* located and resolved */
    bool fuzzy;   /* resolved via a fallback pattern */
    bool armed;   /* hardware breakpoint installed */
    bool retired; /* one-shot site that has fired and given its register back */

    unsigned long address; /* VA of the trap instruction */

    struct tk_action action; /* written only while disarmed */

    struct perf_event* __percpu* breakpoints; /* one event per CPU */
    atomic64_t hits;
    atomic64_t faults;
};

/*
 * A located game, with references held on the task and on its mm (mm_count
 * via mmgrab, not mm_users: the mm is only ever compared, never used).  The
 * caller owns those references and must transfer them into the target state
 * (or drop them with tk_release_game()) when done.
 */
struct tk_game_ref
{
    struct task_struct* task;
    struct mm_struct* mm;
    pid_t pid;
    unsigned long image_base;
    unsigned long image_size;

    /* Executable mappings inside [image_base, image_base + image_size).
     * Scanning only these skips the bulk of the image and eliminates false
     * pattern matches in data sections. */
    struct tk_address_range exec_ranges[TK_MAX_RANGES];
    unsigned int exec_range_count;

    /* Readable, non-executable mappings inside the same window: where the
     * image keeps its string literals. */
    struct tk_address_range data_ranges[TK_MAX_RANGES];
    unsigned int data_range_count;
};

/*
 * Everything one registered target owns.  The trap handler reaches the site
 * through the breakpoint's overflow_handler_context and the target through
 * the site's back pointer, so state is reachable without any compile-time
 * global.
 *
 * Locking rules (invariants the framework relies on):
 *
 *   - st->control_lock serialises enable/disable/unregister end to end, so a
 *     disable that has to drop st->lock to cancel the poll cannot be
 *     interleaved with an enable.  Order: control_lock, then st->lock.  The
 *     work function never takes control_lock, so cancelling the poll while
 *     holding it is safe.
 *   - st->lock serialises every mutation, including the whole of a locate()
 *     call.  The poll work function, the enable/disable paths and
 *     tk_site_resolve() all take it; nothing else may.
 *   - The #DB trap handler runs with interrupts disabled and CANNOT take the
 *     mutex.  It only touches fields that are safe to read locklessly:
 *     st->mm (mmgrabbed, READ_ONCE'd) and per-site atomics, plus site fields
 *     that only change while the site is disarmed.
 *   - "retired" is written only by the poll.  Retiring a one-shot site needs
 *     unregister_wide_hw_breakpoint(), which sleeps, so the trap handler
 *     cannot do it: it just increments hits and the next monitor poll notices.
 *   - cancel_delayed_work_sync() on st->poll_work must NEVER be called while
 *     holding st->lock - the work function takes that same mutex.
 */
struct tk_target_state
{
    struct tk_target* target; /* registered owner */

    struct mutex control_lock; /* enable/disable/unregister; taken before lock */
    struct mutex lock;

    enum tk_state state;
    struct delayed_work poll_work;
    bool enabled; /* enable() seen and not yet disable()d */

    /* Attached game.  task and mm references are held while these are set. */
    struct task_struct* task;
    struct mm_struct* mm; /* trap-handler filter; READ_ONCE in #DB context */
    pid_t game_pid;

    /* The image the attached game runs, re-read from the PE headers. */
    unsigned long image_base;
    unsigned long image_size;

    void* scan_buffer;    /* scratch for the streaming scan, alive while enabled */
    size_t scan_buffer_size;

    struct tk_site sites[TK_MAX_SITES];

    /* On the framework's list of registered targets while registered. */
    struct list_head list;
};

/* ------------------------------------------------------------------ */
/* tk_main.c                                                          */
/* ------------------------------------------------------------------ */

/* Register/unregister are public (tk.h).  No other entry points. */

/* ------------------------------------------------------------------ */
/* tk_target.c                                                        */
/* ------------------------------------------------------------------ */

/* The poll work function; referenced by REGISTER's INIT_DELAYED_WORK. */
void tk_poll(struct work_struct* work);

/* ------------------------------------------------------------------ */
/* tk_bp.c                                                            */
/* ------------------------------------------------------------------ */

/*
 * Install / remove the execute breakpoint for a site.
 *
 * Context: sleepable, st->lock held.  The site's action must be complete and
 * must not change while it is armed.
 *
 * tk_arm_site() returns 0 or a negative errno.
 */
int tk_arm_site(struct tk_site* site);
void tk_disarm_site(struct tk_site* site);
void tk_disarm_all(struct tk_target_state* st);

/* ------------------------------------------------------------------ */
/* tk_process.c                                                       */
/* ------------------------------------------------------------------ */

/*
 * Look for a running process that maps the named image (a PE file, matched
 * case-insensitively on its basename).
 *
 * Context: sleepable.
 * Returns 0 and fills *out (holding task + mm references) on success,
 * -ESRCH when no such process exists right now.
 */
int tk_find_game(struct tk_game_ref* out, const char* image_name);

/* Drop the references held by a successful tk_find_game(). */
void tk_release_game(struct tk_game_ref* game);

/*
 * Has the attached task exited?
 *
 * Deliberately not pid_alive(): that only becomes false once the zombie has
 * been reaped by its parent, which can be arbitrarily late.  exit_state and
 * a dropped mm both flip as soon as the process stops being able to execute,
 * which is exactly when the breakpoints stop being useful.
 */
bool tk_task_is_alive(struct task_struct* task);

/* ------------------------------------------------------------------ */
/* tk_remote.c (the sleepable read is internal; see tk.h)             */
/* ------------------------------------------------------------------ */

/*
 * As tk_read_remote_exact(), but returns the number of bytes actually
 * copied, which is short (possibly 0) when the range runs into an unmapped
 * hole.  Callers must check.
 */
int tk_read_remote(struct task_struct* task, unsigned long address, void* destination, size_t length);

#endif /* TK_INTERNAL_H */
