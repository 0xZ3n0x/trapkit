/*
 * tk_bp.c - per-CPU perf execute breakpoints plus the #DB handler that runs a
 * site's action and steps over the trapped instruction.
 *
 * No byte of the game is ever modified.  The debug registers make the CPU
 * stop just before the instruction; the handler performs the substitutions
 * the site's action describes - or nothing at all, for a plain skip - and
 * then moves RIP past the instruction, so the original code never executes.
 * It knows nothing about which site is which; that knowledge lives in the
 * action each site is resolved with.
 */
#include <asm/ptrace.h>
#include <linux/err.h>
#include <linux/hw_breakpoint.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/sched.h>

#include "tk_internal.h"

/*
 * Breakpoint hit.
 *
 * Context: #DB exception, interrupts disabled, running as the thread that
 * trapped.  Only lock-free work is permitted here - atomics, READ_ONCE and
 * the pagefault-disabled put_user in tk_write_u32_trap.  No allocation, no
 * sleeping, no printk.
 *
 * The site's action was written while it was still disarmed and stays
 * immutable while it is armed, so the handler reads it plainly.
 *
 * The breakpoints are installed per CPU rather than per task, so they fire
 * for whoever executes that address; the mm comparison is what keeps every
 * other process on the machine unaffected.  Returning without touching RIP
 * lets such a thread execute the instruction normally.
 */
static void tk_breakpoint_hit(struct perf_event* event, struct perf_sample_data* data, struct pt_regs* regs)
{
    struct tk_site* site = event->overflow_handler_context;
    struct mm_struct* game_mm = READ_ONCE(site->target->state->mm);
    const struct tk_action* action = &site->action;
    unsigned int i;

    if (!game_mm || current->mm != game_mm || !user_mode(regs))
    {
        return;
    }

    atomic64_inc(&site->hits);

    switch (action->kind)
    {
    case TK_ACT_SKIP:
        /* Nothing to substitute: the lea that loads a logo movie's name
         * simply never happens.  Stepping over it leaves exactly the state
         * seven NOPs would - lea writes no flags and its only effect is the
         * register it loads - so this site cannot fault at all. */
        break;

    case TK_ACT_STORE32:
        for (i = 0; i < action->store_count; i++)
        {
            const struct tk_store32* store = &action->stores[i];
            unsigned long base = regs_get_register(regs, store->base_reg);
            u32 value = store->live ? READ_ONCE(*store->live) : store->imm;

            if (tk_write_u32_trap(base + store->disp, value))
            {
                atomic64_inc(&site->faults);
                return; /* let the stock store(s) run this once */
            }
        }
        break;

    case TK_ACT_CALLBACK:
        if (action->callback(site, regs) == TK_RUN_ORIGINAL)
        {
            return; /* the site's own code asks for the original instruction */
        }
        break;
    }

    /*
     * Step over the emulated instruction(s).  A failed store returns early
     * instead, which is deliberate: skipping a store whose substitute never
     * landed would leave whatever stale value the field held before.  Falling
     * back to the stock instruction is safe even after a partial success,
     * because the stock stores overwrite every field they themselves address.
     * The perf breakpoint code has already set EFLAGS.RF, so resuming cannot
     * re-trigger the same trap.
     */
    regs->ip += action->skip_len;
}

int tk_arm_site(struct tk_site* site)
{
    struct perf_event_attr attr;
    int ret;

    if (site->armed)
    {
        return 0;
    }
    if (!site->found)
    {
        return -ENODATA;
    }

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = site->address;
    /* x86 requires bp_len == sizeof(long) for execute breakpoints; the
     * hardware ignores the length field for RW=00 and matches the exact
     * address regardless. */
    attr.bp_len = sizeof(unsigned long);
    attr.sample_period = 1;

    site->breakpoints = register_wide_hw_breakpoint(&attr, tk_breakpoint_hit, site);
    /* register_wide_hw_breakpoint() returns an ERR_PTR in the percpu pointer
     * itself, so the error check has to launder it through an integer: casting
     * a __percpu pointer straight to void * trips the compiler's named
     * address space check.  This is what the in-tree hw_breakpoint samples do. */
    if (IS_ERR((void __force*)(unsigned long)site->breakpoints))
    {
        ret = PTR_ERR((void __force*)(unsigned long)site->breakpoints);
        site->breakpoints = NULL;
        return ret;
    }

    site->armed = true;
    return 0;
}

/*
 * unregister_wide_hw_breakpoint() releases the debug registers on every CPU
 * and waits for any in-flight handler, so once it returns the site's decoded
 * fields are safe to overwrite.
 */
void tk_disarm_site(struct tk_site* site)
{

    if (site->breakpoints)
    {
        unregister_wide_hw_breakpoint(site->breakpoints);
        site->breakpoints = NULL;
    }
    site->armed = false;
}

void tk_disarm_all(struct tk_target_state* st)
{
    unsigned int i;

    for (i = 0; i < st->target->site_count; i++)
    {
        tk_disarm_site(&st->sites[i]);
    }
}
