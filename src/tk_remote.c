/*
 * tk_remote.c - the memory-access primitives that touch a game's process.
 *
 * Keeping them in one small unit makes the context rule auditable at a
 * glance: reads are sleepable and may only run on framework workqueues,
 * writes are trap-context and may only run inside the #DB handler
 * (an exported helper, because a TK_ACT_CALLBACK runs there too).
 */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "tk_internal.h"

/* Lowest address we will ever believe is a real mapping.  The upper bound is
 * the kernel's own TASK_SIZE_MAX, which follows 4- vs 5-level paging. */
#define TK_MIN_USER_ADDRESS 0x10000UL

EXPORT_SYMBOL_GPL(tk_address_plausible);

bool tk_address_plausible(unsigned long address)
{
    return address >= TK_MIN_USER_ADDRESS && address < TASK_SIZE_MAX;
}

/* Context: sleepable.  Must not be called with the target's mmap_lock held. */
int tk_read_remote(struct task_struct* task, unsigned long address, void* destination, size_t length)
{
    if (!task || !tk_address_plausible(address) || length == 0)
    {
        return 0;
    }
    return access_process_vm(task, address, destination, length, 0);
}

EXPORT_SYMBOL_GPL(tk_read_remote_exact);

int tk_read_remote_exact(struct task_struct* task, unsigned long address, void* destination, size_t length)
{
    int copied = tk_read_remote(task, address, destination, length);

    return (copied == (int)length) ? 0 : -EFAULT;
}

/* Context: #DB trap handler only. */
EXPORT_SYMBOL_GPL(tk_write_u32_trap);

int tk_write_u32_trap(unsigned long address, u32 value)
{
    int ret;

    pagefault_disable();
    ret = put_user(value, (u32 __user*)address);
    pagefault_enable();
    return ret;
}
