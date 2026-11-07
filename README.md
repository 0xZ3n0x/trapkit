# trapkit

A Linux kernel module that changes the behaviour of a running Windows program
under Wine/Proton **without writing a single byte of its code**: hardware
execute breakpoints trap chosen instructions, and a kernel handler performs
their effect with a substituted value instead. Because nothing is written,
dropping the breakpoints restores the program exactly.

trapkit is only the reusable engine. It knows nothing about any game: the
byte patterns, the decoders and what each site does belong to an
**application module** — a GPL kernel module built against the public API in
[`src/tk.h`](src/tk.h), which owns its own userspace surface (an ioctl device
or similar). The engine itself has none: nothing here accepts addresses,
values or patch descriptions from userspace.

> [!WARNING]
> **Proof of concept, not a product.** Unsigned ring-0 code; a bug can crash
> the whole machine. Not for cheating, not for evading anti-cheat, not for
> programs other than the build its application was derived from, not for
> production or shared machines. Whoever loads and uses it is entirely
> responsible for everything that happens — including the terms of service
> of whatever it is run against. No warranty of any kind.

## Build and run

```sh
make                                    # build/kmod/trapkit.ko
sudo insmod build/kmod/trapkit.ko       # the engine (inert until an app registers)
sudo insmod myapplication.ko            # an app module built against tk.h
```

An application declares its sites and builds with `KBUILD_EXTRA_SYMBOLS`
pointing at the engine's `build/kmod/Module.symvers`. The engine cannot be
unloaded while an application is loaded (kernel refcount). Application exit
must call `tk_target_unregister()` first — that stops the watcher, disarms
every breakpoint on all CPUs, drops the process references, and only then
returns, so unloading the app afterwards is always safe.

Write an application by reading `src/tk.h` (its comments are the API
contract) and the units underneath.

## Repository layout

```
src/
  tk.h             the public API, the only header an application sees
  tk_internal.h    per-target state and internal declarations
  tk_main.c        target registration + module lifecycle
  tk_target.c      the poll state machine, arming, retirement, snapshot
  tk_process.c     process discovery, PE header verification
  tk_remote.c      memory-access primitives
  tk_scan.c        the streaming masked-pattern scanner
  tk_x86.c         x86-64 helpers for the application's decoders
  tk_bp.c          breakpoint arm/disarm and the #DB action runner
Makefile           standalone build of trapkit.ko
LICENSE            GPL-2.0-only
```
