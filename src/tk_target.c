/*
 * tk_target.c - the watcher's lifecycle, driven per registered target.
 *
 * A delayed work item polls for the game, and on finding it drives the whole
 * sequence: locate the REQUIRED sites, arm them all-or-nothing, then locate
 * the OPTIONAL ones as a best-effort step, and tear everything down again
 * when the game exits.  It keeps running across game restarts until
 * disable().
 *
 * Everything here runs on the system workqueue, so sleeping is allowed and
 * st->lock is held for the duration of a poll.  A locate can take a while and
 * will delay a concurrent snapshot; that is the intended trade, because the
 * alternative is a torn view of the state a scan is halfway through building.
 *
 * Locking note: disable() must drop st->lock before
 * cancel_delayed_work_sync(), since the work function takes that same mutex.
 * It holds st->control_lock across the whole sequence instead, so an enable
 * cannot slip into the window where st->lock is free.
 *
 * The poll runs on system_long_wq, not system_wq: a scan reads the whole
 * executable image and holds st->lock while it does.
 */
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "tk_internal.h"

/*
 * How often to look for the game.  A game's boot-time site may execute only
 * once, so the search interval plus the time to scan and arm is the window
 * the locate has to beat; keep it short.
 */
#define TK_POLL_SEARCH_INTERVAL_MS 300

/* Once armed there is nothing to do but notice the game exiting. */
#define TK_POLL_MONITOR_INTERVAL_MS 2000

/* Streaming buffer for the pattern scan.  Allocated while enabled so no
 * allocation happens on the path that races the game's boot. */
#define TK_SCAN_BUFFER_SIZE (1UL << 20)

/* ------------------------------------------------------------------ */
/* Attach / detach                                                     */
/* ------------------------------------------------------------------ */

/*
 * Give up on patching this instance, but stay attached to the task so the
 * poll can still see it exit and try again on the next launch.  Without
 * this the poll would drop straight back to SEARCHING and rescan the whole
 * image every few hundred milliseconds for as long as an unpatchable game
 * keeps running.
 *
 * The mm reference (an mm_count, see tk_find_game()) is released here: only
 * the trap handler needs it, and it has no breakpoint left to fire.
 *
 * Context: st->lock held.
 */
static void abandon_game(struct tk_target_state* st)
{
    unsigned int i;

    tk_disarm_all(st);

    if (st->mm)
    {
        mmdrop(st->mm);
        WRITE_ONCE(st->mm, NULL);
    }

    /* Keep the hit/fault counters so a snapshot after the game exits still
     * shows what the session did; only the location is stale. */
    for (i = 0; i < st->target->site_count; i++)
    {
        st->sites[i].found = false;
        st->sites[i].fuzzy = false;
        st->sites[i].retired = false;
        st->sites[i].address = 0;
    }
}

/* Full teardown: abandon the game and stop tracking the task entirely.
 * Context: st->lock held. */
static void forget_game(struct tk_target_state* st)
{
    abandon_game(st);

    if (st->task)
    {
        put_task_struct(st->task);
        st->task = NULL;
    }
    st->game_pid = 0;
    st->image_base = 0;
    st->image_size = 0;
}

/* Context: st->lock held.  Adopts the references held by *game. */
static void adopt_game(struct tk_target_state* st, struct tk_game_ref* game)
{
    st->task = game->task;
    st->game_pid = game->pid;
    st->image_base = game->image_base;
    st->image_size = game->image_size;

    /* Published last: it is the filter the trap handler tests, and no
     * breakpoint exists yet, so ordering here is for clarity not safety. */
    WRITE_ONCE(st->mm, game->mm);

    game->task = NULL;
    game->mm = NULL;
}

/* ------------------------------------------------------------------ */
/* Site resolution                                                     */
/* ------------------------------------------------------------------ */

EXPORT_SYMBOL_GPL(tk_site_resolve);

int tk_site_resolve(struct tk_target* t, unsigned int idx, unsigned long address, const struct tk_action* a)
{
    struct tk_target_state* st;
    struct tk_site* site;

    if (!t || !t->state || idx >= t->site_count || !a)
    {
        return -EINVAL;
    }
    st = t->state;
    lockdep_assert_held(&st->lock);

    site = &st->sites[idx];

    if (site->found)
    {
        /* A pattern listed before it already won; a fallback must not
         * overwrite the earlier match. */
        return -EEXIST;
    }
    if (!tk_address_plausible(address) || address < st->image_base || address >= st->image_base + st->image_size)
    {
        /* The scans only cover mappings inside the image, but a match is
         * about to become a breakpoint address, so bound it explicitly. */
        pr_warn("trapkit: %s match at %#lx falls outside the image\n", site->desc->name, address);
        return -EINVAL;
    }

    site->address = address;
    site->action = *a;
    site->fuzzy = (a->flags & TK_ACTION_FUZZY) != 0;
    site->found = true;
    site->retired = false;

    /* Per-session counters: this is also what makes "hits > 0" mean "fired
     * during this launch" for a one-shot site's retirement. */
    atomic64_set(&site->hits, 0);
    atomic64_set(&site->faults, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Locate -> arm                                                       */
/* ------------------------------------------------------------------ */

/* Context: st->lock held. */
static unsigned int count_required_sites(struct tk_target_state* st)
{
    const struct tk_target* t = st->target;
    unsigned int count = 0;
    unsigned int i;

    for (i = 0; i < t->site_count; i++)
    {
        if (t->sites[i].phase == TK_PHASE_REQUIRED)
        {
            count++;
        }
    }
    return count;
}

/* Context: st->lock held.  Arms every REQUIRED site or none. */
static int arm_required_sites(struct tk_target_state* st)
{
    const struct tk_target* t = st->target;
    unsigned int i;

    for (i = 0; i < t->site_count; i++)
    {
        int ret;

        if (t->sites[i].phase != TK_PHASE_REQUIRED)
        {
            continue;
        }
        ret = tk_arm_site(&st->sites[i]);
        if (ret)
        {
            pr_err("trapkit: failed to arm %s: %d\n", st->sites[i].desc->name, ret);
            tk_disarm_all(st);
            return ret;
        }
    }
    return 0;
}

/*
 * Locate the OPTIONAL sites and arm them one by one.
 *
 * Unlike the required sites these are individually survivable: almost always
 * the reason a site cannot be armed is "no debug register left", since four
 * sites is every one the hardware has.  Whatever the reason, the required
 * sites stay armed and the session keeps its guarantee.
 *
 * Context: st->lock held, sleepable.  Returns the number of sites armed.
 */
static unsigned int arm_optional_sites(struct tk_target_state* st)
{
    const struct tk_target* t = st->target;
    unsigned int armed = 0;
    unsigned int i;

    for (i = 0; i < t->site_count; i++)
    {
        struct tk_site* site = &st->sites[i];
        int ret;

        if (t->sites[i].phase != TK_PHASE_OPTIONAL)
        {
            continue;
        }
        if (!site->found || site->armed)
        {
            continue;
        }

        ret = tk_arm_site(site);
        if (ret)
        {
            pr_warn("trapkit: %s located at %#lx but not armed (%d); that site is skipped this session\n",
                    site->desc->name, site->address, ret);
            continue;
        }
        armed++;
    }
    return armed;
}

/* Fill the view of the image that locate() works on.  Context: st->lock held
 * (so is everything on this path), and *game outlives the locate calls. */
static void build_image(struct tk_target_state* st, const struct tk_game_ref* game, struct tk_image* img)
{
    memset(img, 0, sizeof(*img));
    img->task = st->task;
    img->base = st->image_base;
    img->size = st->image_size;
    img->exec = game->exec_ranges;
    img->exec_count = game->exec_range_count;
    img->data = game->data_ranges;
    img->data_count = game->data_range_count;
    img->scan_buffer = st->scan_buffer;
    img->scan_buffer_size = st->scan_buffer_size;
}

/*
 * One search attempt: is the game running, and can it be patched?
 *
 * Context: st->lock held, sleepable.  Returns the state to move to.
 */
static enum tk_state try_patch_game(struct tk_target_state* st)
{
    struct tk_target* t = st->target;
    struct tk_game_ref game;
    struct tk_image img;
    ktime_t started;
    unsigned int required;
    unsigned int resolved = 0;
    unsigned int i;
    int ret;

    if (tk_find_game(&game, t->image_name))
    {
        return TK_STATE_SEARCHING; /* not running yet */
    }

    started = ktime_get();
    adopt_game(st, &game);
    build_image(st, &game, &img);

    pr_info("trapkit: found %s pid %d, image %#lx+%#lx, %u executable and %u data range(s)\n", t->image_name,
            st->game_pid, st->image_base, st->image_size, game.exec_range_count, game.data_range_count);

    /* REQUIRED first, and in one locate call: the application scans every
     * pattern in a single pass, which is what wins the race against a site
     * that executes only during the game's boot.  Nothing optional is worth
     * delaying that race for. */
    ret = t->locate(t, &img, TK_PHASE_REQUIRED);
    if (ret)
    {
        /* The application printed why; the game is left untouched. */
        abandon_game(st);
        return TK_STATE_FAILED;
    }

    required = count_required_sites(st);
    for (i = 0; i < t->site_count; i++)
    {
        if (t->sites[i].phase == TK_PHASE_REQUIRED && st->sites[i].found)
        {
            resolved++;
        }
    }
    if (resolved != required)
    {
        pr_warn("trapkit: only %u of %u required site(s) resolved; leaving the game unpatched\n", resolved,
                required);
        abandon_game(st);
        return TK_STATE_FAILED;
    }

    if (arm_required_sites(st))
    {
        abandon_game(st);
        return TK_STATE_FAILED;
    }

    pr_info("trapkit: %s armed in %lld us -", t->image_name, ktime_us_delta(ktime_get(), started));
    for (i = 0; i < st->target->site_count; i++)
    {
        if (st->target->sites[i].phase == TK_PHASE_REQUIRED)
        {
            pr_cont(" %s %#lx%s", st->sites[i].desc->name, st->sites[i].address, st->sites[i].fuzzy ? " (fuzzy)" : "");
        }
    }
    pr_cont("\n");

    /* Only now, with the required sites armed: the optional ones are worth
     * having but never worth delaying the boot race for. */
    t->locate(t, &img, TK_PHASE_OPTIONAL);

    /* Best effort throughout: a failure here costs one optional site, never
     * the game. */
    arm_optional_sites(st);

    return TK_STATE_ARMED;
}

/* ------------------------------------------------------------------ */
/* The poll                                                            */
/* ------------------------------------------------------------------ */

/*
 * Give a one-shot site's debug register back once it has done its job.
 *
 * The trap handler cannot do this itself - unregistering sleeps - so it only
 * counts the hit and this notices on the next monitor poll.  The couple of
 * seconds in between cost nothing: another hit is just another skipped
 * instruction.
 *
 * Context: st->lock held.
 */
static void retire_spent_sites(struct tk_target_state* st)
{
    struct tk_target* t = st->target;
    unsigned int i;

    for (i = 0; i < t->site_count; i++)
    {
        struct tk_site* site = &st->sites[i];

        if (!(t->sites[i].flags & TK_SITE_ONESHOT) || !site->armed || !atomic64_read(&site->hits))
        {
            continue;
        }

        tk_disarm_site(site);
        site->retired = true;
        pr_info("trapkit: %s fired at %#lx; breakpoint retired, debug register released\n", site->desc->name,
                site->address);
    }
}

/* Context: st->lock held. */
static void report_session_end(struct tk_target_state* st)
{
    struct tk_target* t = st->target;
    unsigned int i;

    pr_info("trapkit: pid %d exited\n", st->game_pid);
    for (i = 0; i < t->site_count; i++)
    {
        pr_info("trapkit:   %-14s hits %lld faults %lld\n", st->sites[i].desc->name,
                atomic64_read(&st->sites[i].hits), atomic64_read(&st->sites[i].faults));
    }
}

void tk_poll(struct work_struct* work)
{
    struct tk_target_state* st = container_of(work, struct tk_target_state, poll_work.work);
    unsigned int delay_ms;

    mutex_lock(&st->lock);

    if (!st->enabled)
    {
        /* Disabled while this poll was queued; the disable path does the
         * teardown, so just stop rescheduling. */
        mutex_unlock(&st->lock);
        return;
    }

    switch (st->state)
    {
    case TK_STATE_SEARCHING:
        st->state = try_patch_game(st);
        break;

    case TK_STATE_ARMED:
        retire_spent_sites(st);
        fallthrough;
    case TK_STATE_FAILED:
        if (!tk_task_is_alive(st->task))
        {
            if (st->state == TK_STATE_ARMED)
            {
                report_session_end(st);
            }
            forget_game(st);
            st->state = TK_STATE_SEARCHING;
        }
        break;

    case TK_STATE_DISABLED:
        break;
    }

    delay_ms = (st->state == TK_STATE_SEARCHING) ? TK_POLL_SEARCH_INTERVAL_MS : TK_POLL_MONITOR_INTERVAL_MS;
    queue_delayed_work(system_long_wq, &st->poll_work, msecs_to_jiffies(delay_ms));

    mutex_unlock(&st->lock);
}

/* ------------------------------------------------------------------ */
/* Control surface                                                     */
/* ------------------------------------------------------------------ */

EXPORT_SYMBOL_GPL(tk_target_enable);

int tk_target_enable(struct tk_target* t)
{
    struct tk_target_state* st;
    void* buffer;

    if (!t || !t->state)
    {
        return -EINVAL;
    }
    st = t->state;

    mutex_lock(&st->control_lock);

    /* control_lock is held, so st->enabled cannot change under us; reading
     * it without st->lock is fine because only control_lock holders write it. */
    if (st->enabled)
    {
        /* Already watching: nothing to do (the frame rate is the owner's
         * business, applied on the owner's side before this call). */
        mutex_unlock(&st->control_lock);
        return 0;
    }

    /* Allocate before taking st->lock: vmalloc can sleep for a while and
     * there is no reason to hold up a snapshot for it. */
    buffer = vmalloc(TK_SCAN_BUFFER_SIZE);
    if (!buffer)
    {
        mutex_unlock(&st->control_lock);
        return -ENOMEM;
    }

    mutex_lock(&st->lock);

    st->scan_buffer = buffer;
    st->scan_buffer_size = TK_SCAN_BUFFER_SIZE;
    st->enabled = true;
    st->state = TK_STATE_SEARCHING;

    /* Fire immediately: the game may already be running. */
    queue_delayed_work(system_long_wq, &st->poll_work, 0);

    mutex_unlock(&st->lock);
    mutex_unlock(&st->control_lock);
    return 0;
}

EXPORT_SYMBOL_GPL(tk_target_disable);

void tk_target_disable(struct tk_target* t)
{
    struct tk_target_state* st;
    void* buffer;

    if (!t || !t->state)
    {
        return;
    }
    st = t->state;

    mutex_lock(&st->control_lock);
    mutex_lock(&st->lock);
    if (!st->enabled)
    {
        mutex_unlock(&st->lock);
        mutex_unlock(&st->control_lock);
        return;
    }
    /* Clear this first so a poll already in flight stops rescheduling. */
    st->enabled = false;
    mutex_unlock(&st->lock);

    /* Must be outside st->lock: tk_poll() takes it.  control_lock stays
     * held, which is what keeps an enable out of this window. */
    cancel_delayed_work_sync(&st->poll_work);

    mutex_lock(&st->lock);
    forget_game(st);
    st->state = TK_STATE_DISABLED;
    buffer = st->scan_buffer;
    st->scan_buffer = NULL;
    st->scan_buffer_size = 0;
    mutex_unlock(&st->lock);
    mutex_unlock(&st->control_lock);

    vfree(buffer);
    pr_info("trapkit: %s disabled; the image is byte-identical vanilla again\n", t->image_name);
}

EXPORT_SYMBOL_GPL(tk_target_snapshot);

int tk_target_snapshot(struct tk_target* t, struct tk_snapshot* out)
{
    struct tk_target_state* st;
    unsigned int i;
    int ret = 0;

    memset(out, 0, sizeof(*out));
    if (!t || !t->state)
    {
        out->state = TK_STATE_DISABLED;
        return 0;
    }
    st = t->state;

    if (mutex_lock_interruptible(&st->lock))
    {
        return -ERESTARTSYS;
    }

    out->state = st->state;
    out->game_pid = st->game_pid;
    out->image_base = st->image_base;
    out->image_size = st->image_size;
    out->site_count = t->site_count;

    for (i = 0; i < t->site_count; i++)
    {
        struct tk_site_snapshot* snap = &out->sites[i];
        const struct tk_site* site = &st->sites[i];

        snap->address = site->address;
        snap->hits = atomic64_read(&site->hits);
        snap->faults = atomic64_read(&site->faults);
        snap->found = site->found;
        snap->fuzzy = site->fuzzy;
        snap->armed = site->armed;
        snap->retired = site->retired;
    }

    mutex_unlock(&st->lock);
    return ret;
}
