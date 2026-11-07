/*
 * tk_main.c - target registration: the framework's front door.
 *
 * A target is a registered, enabled, then unregistered lifetime.  This unit
 * owns the list of registered targets and the bookkeeping that pins and
 * releases their state.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "tk_internal.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trap-and-substitute patching engine via hardware execute breakpoints");
MODULE_VERSION("1.0");

/* The registered targets; entries exist only between register/unregister. */
static LIST_HEAD(tk_targets);
static DEFINE_MUTEX(tk_targets_lock);

/* Applications call these through tk.h; the list itself stays private. */
EXPORT_SYMBOL_GPL(tk_target_register);

int tk_target_register(struct tk_target* t)
{
    struct tk_target_state* st;
    unsigned int i;

    if (!t || !t->owner || !t->image_name || !t->locate || !t->sites || !t->site_count ||
        t->site_count > TK_MAX_SITES)
    {
        pr_warn("trapkit: target registration is incomplete\n");
        return -EINVAL;
    }
    if (t->api_version != TK_API_VERSION)
    {
        pr_warn("trapkit: %s built against API %u, framework has %u: rebuild the application\n",
                t->image_name, t->api_version, TK_API_VERSION);
        return -EINVAL;
    }

    st = kzalloc(sizeof(*st), GFP_KERNEL);
    if (!st)
    {
        return -ENOMEM;
    }

    st->target = t;
    mutex_init(&st->control_lock);
    mutex_init(&st->lock);
    INIT_DELAYED_WORK(&st->poll_work, tk_poll);
    for (i = 0; i < t->site_count; i++)
    {
        struct tk_site* site = &st->sites[i];

        site->target = t;
        site->index = i;
        site->desc = &t->sites[i];
    }

    /* The app has no thread running between register and unregister that
     * could see a half-formed state, so t->state can be published as soon
     * as the object is consistent. */
    mutex_lock(&tk_targets_lock);
    list_add_tail(&st->list, &tk_targets);
    mutex_unlock(&tk_targets_lock);
    t->state = st;

    pr_info("trapkit: target %s registered (%u site(s))\n", t->image_name, t->site_count);
    return 0;
}

EXPORT_SYMBOL_GPL(tk_target_unregister);

void tk_target_unregister(struct tk_target* t)
{
    struct tk_target_state* st;

    if (!t || !t->state)
    {
        return;
    }
    st = t->state;

    mutex_lock(&tk_targets_lock);
    list_del(&st->list);
    mutex_unlock(&tk_targets_lock);

    /*
     * Synchronous teardown, in this order:
     * 1. the watcher stops: control_lock held across the whole sequence, the
     *    poll cancelled synchronously,
     * 2. every site disarmed: unregister_wide_hw_breakpoint() releases the
     *    debug register on each CPU with an IPI, and the #DB handler runs
     *    with interrupts off, so no handler can still be inside the
     *    owner's callback or a live pointer once this returns,
     * 3. the task and mm references dropped by forget_game().
     * Only after all three is the owner's text free to be freed - which is
     * why the application calls this first thing in its module_exit.
     */
    tk_target_disable(t);

    t->state = NULL;
    kfree(st);
}

static int __init tk_init(void)
{
    pr_info("trapkit: framework ready (%u site(s) per target, API %d)\n", TK_MAX_SITES, TK_API_VERSION);
    return 0;
}

static void __exit tk_exit(void)
{
    bool leaked;

    mutex_lock(&tk_targets_lock);
    leaked = !list_empty(&tk_targets);
    mutex_unlock(&tk_targets_lock);

    /*
     * Unregistering is the application's job, first thing in its exit; a
     * target still on the list at this point means the owner skipped its
     * teardown.  The state would leak and - worse - its breakpoints would
     * outlive... they cannot: the owner's module text is gone either way,
     * so warn loudly and make the bug findable in dmesg.
     */
    if (leaked)
    {
        WARN_ON(true);
    }
}

module_init(tk_init);
module_exit(tk_exit);
