/*
 * tk.h - the trap kit's public API, and the only header an application
 * module sees.
 *
 * trapkit.ko is the reusable engine: it watches for a process by image
 * name, scans its PE image for byte patterns, verifies the instructions it
 * finds, arms per-CPU execute breakpoints on them, runs a small description
 * of what a hit does, and gives one-shot debug registers back.  It knows
 * nothing about any particular game.
 *
 * An application module owns the game-specific knowledge: the byte patterns,
 * the instruction decoders, and which site uses which action.  It describes
 * itself with a struct tk_target and hands it to tk_target_register(); from
 * then on the framework drives the whole find -> scan -> decode -> arm ->
 * retire -> teardown lifecycle, calling back into the application's
 * locate() to turn scan matches into resolved sites.
 *
 * Boundary: no userspace-programmable addresses or actions.  What gets
 * patched where is decided only by kernel code compiled into the
 * application module.  Neither trapkit nor the application offers an ioctl that
 * takes an address or a patch description.
 */
#ifndef TK_H
#define TK_H

#include <linux/types.h>

struct mm_struct;
struct tk_site;
struct pt_regs;
struct task_struct;

#define TK_API_VERSION 1
#define TK_MAX_SITES   8   /* per target; the hardware only has four debug registers */
#define TK_MAX_STORES  2
#define TK_MAX_RANGES  16  /* clipped image mappings tracked per kind, see tk_image */

/*
 * Which half of a site's lifecycle a locate() call drives.  Every REQUIRED
 * site has to resolve, or the game is left alone; OPTIONAL sites are
 * best-effort and are skipped if they cannot be found or armed.  The
 * framework locates REQUIRED before OPTIONAL, so whatever races the game's
 * boot is never delayed by best-effort work.
 */
enum tk_phase
{
    TK_PHASE_REQUIRED = 0,
    TK_PHASE_OPTIONAL,
};

/* Outcome a callback asks for: emulate the original instruction, or skip it. */
enum tk_hit
{
    TK_RUN_ORIGINAL = 0,
    TK_SKIP,
};

/* Watcher lifecycle.  Same progression, and the same numeric values, as the
 * NP_WATCHER_* states a status snapshot carries. */
enum tk_state
{
    TK_STATE_DISABLED = 0,
    TK_STATE_SEARCHING,
    TK_STATE_ARMED,
    TK_STATE_FAILED,
};

/* One clipped mapping inside the game's image. */
struct tk_address_range
{
    unsigned long start;
    unsigned long end; /* exclusive */
};

/*
 * A masked byte pattern.  mask[i] == 0xFF pins bytes[i]; mask[i] == 0x00 is
 * a wildcard, in which case bytes[i] must be 0 so that the match reduces to
 * (data[i] & mask[i]) == bytes[i] with no special-casing.
 *
 * Some matches cannot be expressed as bytes alone - a RIP-relative operand
 * encodes a displacement whose meaning depends on where the instruction sits.
 * An optional verify callback gets the final say on such a candidate: the byte
 * match is only accepted if it returns true, and the scan otherwise carries on
 * from the next offset looking for a better one.
 *
 * verify() must be pure: it runs inside the scan loop and may only read the
 * length bytes it is handed.  No sleeping, no allocation, no remote reads -
 * make the pattern long enough that everything it needs is already in range.
 */
struct tk_pattern
{
    const u8* bytes;
    const u8* mask;
    size_t length;
    const char* name; /* diagnostics only */

    /* match: the pattern->length bytes that matched.  va: their address in
     * the target.  context: whatever the pattern's owner attached. */
    bool (*verify)(const u8* match, unsigned long va, const void* context);
    const void* context;
};

struct tk_scan_result
{
    bool found;
    unsigned long address; /* VA of the first byte of the match */
};

/*
 * Search ranges for every pattern in one streaming pass.
 *
 * Context: sleepable; reschedules between chunks.  results[] must hold
 * pattern_count entries and is fully initialised here.  Each pattern stops
 * being tested once it has matched (and been accepted by its verify callback,
 * if it has one), and the scan returns early once all of them have.  Unreadable
 * pages are skipped rather than aborting the scan.
 *
 * Returns the number of patterns matched.
 */
unsigned int tk_scan_ranges(struct task_struct* task, const struct tk_address_range* ranges, unsigned int range_count,
                             const struct tk_pattern* patterns, unsigned int pattern_count,
                             struct tk_scan_result* results, void* buffer, size_t buffer_size);

/* The substitution mechanisms the trap handler knows. */
enum tk_action_kind
{
    TK_ACT_SKIP = 0, /* step over the instruction, touch nothing */
    TK_ACT_STORE32,  /* perform one or more 32-bit stores, then step over */
    TK_ACT_CALLBACK, /* ask the owning module, in #DB context */
};

/* Action flag: the match came from a fallback pattern (diagnostic only). */
#define TK_ACTION_FUZZY 0x01

/*
 * One 32-bit store an TK_ACT_STORE32 action performs on a hit.
 *
 * base_reg is an offset inside struct pt_regs; the handler turns it back into
 * the trapped thread's register with regs_get_register() and adds disp.  The
 * value comes from *live if that pointer is set (read locklessly on every
 * hit, so the owning module can retarget it while armed), otherwise from imm.
 */
struct tk_store32
{
    u8 base_reg;
    s32 disp;
    const u32* live;
    u32 imm;
};

/*
 * How a site reacts to a hit.  Any failed store counts one fault and leaves
 * RIP alone, so the original instruction runs instead - see tk_bp.c for why
 * that is safe even after a partial success.  All of an action is written
 * only while its site is disarmed, so the #DB handler reads it plainly.
 */
struct tk_action
{
    enum tk_action_kind kind;
    u8 skip_len;                               /* RIP advance past the emulated instruction(s) */
    u8 flags;
    u8 store_count;
    struct tk_store32 stores[TK_MAX_STORES]; /* TK_ACT_STORE32 */
    /* TK_ACT_CALLBACK, #DB context.  Only lock-free work is permitted. */
    enum tk_hit (*callback)(struct tk_site* site, struct pt_regs* regs);
};

/* Site description flag: the site fires once per session and is retired as
 * soon as it has, giving its debug register back. */
#define TK_SITE_ONESHOT 0x01

struct tk_site_desc
{
    const char* name;     /* diagnostics and the status snapshot */
    enum tk_phase phase; /* see above for what each phase means */
    unsigned int flags;   /* TK_SITE_ONESHOT */
};

/*
 * What an image's locate() call is handed.  Valid only during the call: the
 * ranges it points into belong to the framework's target state.  task and the
 * ranges come from the framework's own process walk; scan_buffer is the
 * framework's scratch space.
 *
 * Context: sleepable, and the framework's per-target lock is held for the
 * whole call (that is what makes tk_site_resolve() safe).  Read game memory
 * freely with tk_read_remote_exact(); do not take locks of your own except
 * your module's private ones.
 */
struct tk_image
{
    struct task_struct* task;
    unsigned long base, size; /* PE image load address and SizeOfImage */

    /* Executable mappings inside the image (where patch sites live), and
     * readable non-executable ones (where its string literals live). */
    const struct tk_address_range* exec;
    unsigned int exec_count;
    const struct tk_address_range* data;
    unsigned int data_count;

    void* scan_buffer;
    size_t scan_buffer_size;
};

/*
 * One patchable target: everything the framework must know to do its work
 * for one game.  Static data in the application module; the framework only
 * ever reads it.  state is the framework's private per-target object, filled
 * in by tk_target_register().
 */
struct tk_target
{
    unsigned int api_version; /* TK_API_VERSION, checked on register */
    struct module* owner;     /* THIS_MODULE */
    const char* image_name;   /* basename of the mapped file, e.g. "mygame.exe" */

    const struct tk_site_desc* sites;
    unsigned int site_count; /* at most TK_MAX_SITES */

    /*
     * Locate every site of one phase.  Called with the framework's per-target
     * lock held, so the whole phase resolves in one go (a REQUIRED locate must
     * scan once and match every pattern in that pass, to win the race against
     * the game's boot-time timing setup).  Resolve sites with
     * tk_site_resolve(); the framework then checks that every REQUIRED site
     * was resolved and fails the game if not.  Print your own diagnostics:
     * the framework only logs what it itself decides.  Returns 0 on success,
     * negative on failure.
     */
    int (*locate)(struct tk_target* t, const struct tk_image* img, enum tk_phase phase);

    struct tk_target_state* state; /* framework-private, allocated on register */
};

/*
 * Register a target.  Checks api_version and the struct's completeness;
 * returns 0 or a negative errno.  Order on the lifecycle:
 *
 *   register -> enable (watch, patch, watch again across game restarts)
 *            -> disable (stop watching, restore stock behaviour)
 *            -> unregister (immediately before the module is unloaded)
 *
 * The rules that keep the application's memory alive are the lifetime rules:
 * the application's exit must call tk_target_unregister() first, and while
 * the target is registered the kernel's module dependency refcount keeps the
 * framework's own text alive.
 */
int tk_target_register(struct tk_target* t);

/*
 * Synchronous teardown: stop the watcher, disarm every site, drop the task
 * and mm references and free the per-target state.  When it returns no
 * breakpoint on the target exists, no poll can run, and no #DB handler can
 * still be inside the application's callback or live pointer, so the
 * application's text is free to unload.  Call it first thing in the
 * application's module_exit.
 */
void tk_target_unregister(struct tk_target* t);

/*
 * Start watching (or, when already watching, change nothing - the frame rate
 * is the application's business, set it before calling).  Allocates the scan
 * buffer, then polls for the game until disable().  Returns 0 or a negative
 * errno.
 */
int tk_target_enable(struct tk_target* t);

/* Stop watching, disarm everything and detach.  Safe to call when idle. */
void tk_target_disable(struct tk_target* t);

/*
 * A self-consistent snapshot of what the framework is doing for one target.
 * sites[] is filled for the target's site_count entries; the rest is zeroed.
 *
 * Context: sleepable.  Returns 0 or a negative errno (a scan in progress
 * holds the target's lock for a while, so the wait is interruptible).
 */
struct tk_site_snapshot
{
    u64 address;               /* VA of the trap instruction, 0 when not located */
    s64 hits;                  /* trap handler invocations */
    s64 faults;                /* substitutions that could not be written */
    bool found;                /* located by the scanner and accepted by the decoder */
    bool fuzzy;                /* matched via a fallback pattern */
    bool armed;                /* hardware breakpoint currently installed */
    bool retired;              /* one-shot site that has fired and released its debug register */
};

struct tk_snapshot
{
    enum tk_state state;
    pid_t game_pid;
    unsigned long image_base;
    unsigned long image_size;

    unsigned int site_count; /* = target->site_count */
    struct tk_site_snapshot sites[TK_MAX_SITES];
};

int tk_target_snapshot(struct tk_target* t, struct tk_snapshot* out);

/*
 * Resolve one site: record its address, copy the action in, reset its
 * per-session counters and mark it found.  The address is checked against
 * the image bounds; a resolve for an already-found site is refused with
 * -EEXIST so a primary match cannot be overwritten by a fallback.
 *
 * Context: inside locate(), where the framework's per-target lock is held.
 * Returns 0, or a negative errno.
 */
int tk_site_resolve(struct tk_target* t, unsigned int idx, unsigned long address, const struct tk_action* a);

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Read from another process's address space, in full.  Context: sleepable;
 * the target's mmap_lock is taken internally, so do not hold it.
 * Returns 0 or -EFAULT. */
int tk_read_remote_exact(struct task_struct* task, unsigned long address, void* destination, size_t length);

/*
 * Write one 32-bit value into the trapped thread's own address space.
 * Context: #DB trap handler context (as used by an TK_ACT_CALLBACK).
 * Returns 0 on success, non-zero if the address was not writable.
 */
int tk_write_u32_trap(unsigned long address, u32 value);

/* Coarse plausibility filter for a userspace address: rejects the NULL page
 * and anything in the kernel half of the canonical address space. */
bool tk_address_plausible(unsigned long address);

/* REX, operand/address size, lock, rep and segment override prefixes.  A
 * bare instruction may not be preceded by any of them (see tk_x86.c). */
bool tk_x86_is_prefix(u8 byte);

/* mod=01 rm field -> byte offset of that base register inside struct pt_regs. */
u8 tk_x86_modrm_rm_to_regs(u8 rm);

/*
 * Decode "mov dword [base+disp8], imm32" (opcode C7, mod=01, reg=0, no SIB).
 * Returns 0 and fills base_reg (a pt_regs offset), disp and imm on success;
 * -EINVAL if the bytes are not that encoding.  The caller checks any byte
 * that pins the site's identity (such as the immediate) itself.
 */
int tk_x86_decode_mov_m32_imm32(const u8* code, u8* base_reg, s8* disp, u32* imm);

#endif /* TK_H */
