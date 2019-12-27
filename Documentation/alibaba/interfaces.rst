.. SPDX-License-Identifier: GPL-2.0+

=======================
Cloud Kernel interfaces
=======================

This file collects all the interfaces specific to Cloud Kernel.

memory.wmark_min_adj
====================
    This file is under memory cgroup v1.

    In co-location environment, there are more or less some memory
    overcommitment, then BATCH tasks may break the shared global min
    watermark resulting in all types of applications falling into
    the direct reclaim slow path hurting the RT of LS tasks.
    (NOTE: BATCH tasks tolerate big latency spike even in seconds
    as long as doesn't hurt its overal throughput. While LS tasks
    are very Latency-Sensitive, they may time out or fail in case
    of sudden latency spike lasts like hundreds of ms typically.)

    Actually BATCH tasks are not sensitive to memory latency, they
    can be assigned a strict min watermark which is different from
    that of LS tasks(which can be aissgned a lenient min watermark
    accordingly), thus isolating each other in case of global memory
    allocation.

    memory.wmark_min_adj stands for memcg global WMARK_MIN adjustment,
    it is used to realize separate min watermarks above-mentioned for
    memcgs, its valid value is within [-25, 50], specifically:
    negative value means to be relative to [0, WMARK_MIN],
    positive value means to be relative to [WMARK_MIN, WMARK_LOW].

    For examples::

     -25 means memcg WMARK_MIN is "WMARK_MIN + (WMARK_MIN - 0) * (-25%)"
      50 means memcg WMARK_MIN is "WMARK_MIN + (WMARK_LOW - WMARK_MIN) * 50%"

    Negative memory.wmark_min_adj means high QoS requirements, it can
    allocate below the global WMARK_MIN, which is kind of like the idea
    behind ALLOC_HARDER, see gfp_to_alloc_flags().

    Positive memory.wmark_min_adj means low QoS requirements, thus when
    allocation broke memcg min watermark, it should trigger direct reclaim
    traditionally, and we trigger throttle instead to further prevent them
    from disturbing others. The throttle time is simply linearly proportional
    to the pages consumed below memcg's min watermark. The normal throttle
    time once should be within [1ms, 100ms], and the maximal throttle time
    is 1000ms. The throttle is only triggered under global memory pressure.

    With this interface, we can assign positive values for BATCH memcgs
    and negative values for LS memcgs. Note that root memcg doesn't have
    this file.

    memory.wmark_min_adj default value is 0, and inherit from its parent,
    Note that the final effective wmark_min_adj will consider all the
    hierarchical values, its value is the maximal(most conservative)
    wmark_min_adj along the hierarchy but excluding intermediate default
    values(zero).

    For example::

     The following hierarchy
                     root
                      / \
                     A   D
                    / \
                   B   C
                  / \
                 E   F

     wmark_min_adj:  A -10, B -25, C 0, D 50, E -25, F 50
     wmark_min_eadj: A -10, B -10, C 0, D 50, E -10, F 50

     "echo xxx > memory.wmark_min_adj" set "wmark_min_adj".
     "cat memory.wmark_min_adj" shows the value of "wmark_min_eadj".

memory.exstat
=============
    This file is under memory cgroup v1.

    memory.exstat stands for "extra/extended memory.stat", which is supposed
    to provide hierarchical statistics.

    "wmark_min_throttled_ms" field is the total throttled time in milliseconds
    due to positive memory.wmark_min_adj under global memory pressure.

    "wmark_reclaim_work_ms" field is the total background async page reclaim
    (a.k.a, memcg kswap) work time in milliseconds, including sleep/resched
    time currently, due to excessive usage of memory over wmark_high.

zombie memcgs reaper
====================
    After memcg was deleted, page caches still reference to this memcg
    causing large number of dead(zombie) memcgs in the system. Then it
    slows down access to "/sys/fs/cgroup/cpu/memory.stat", etc due to
    tons of iterations, further causing various latencies. "zombie memcgs
    reaper" is a tool to reclaim these dead memcgs. It has two modes:

    "Background kthread reaper" mode
    --------------------------------
    In this mode, a kthread reaper keeps reclaiming at background,
    some knobs are provided to control the reaper scan behaviour:

    - /sys/kernel/mm/memcg_reaper/scan_interval

      the scan period in second. Default is 5s.

    - /sys/kernel/mm/memcg_reaper/pages_scan

      the scan rate of pages per scan. Default 1310720(5GiB for 4KiB page).

    - /sys/kernel/mm/memcg_reaper/verbose

      output some zombie memcg information for debug purpose. Default off.

    - /sys/kernel/mm/memcg_reaper/reap_background

     on/off switch. Default "0" means off. Write "1" to switch it on.

    "One-shot trigger" mode
    -----------------------
    In this mode, there is no guarantee to finish the reclaim, you may need
    to check and launch multiple rounds as needed.

    - /sys/kernel/mm/memcg_reaper/reap

      users write "1" to trigger one round of zombie memcg reaping.

memory.priority
===============
    Under memory pressure, reclaim and oom would happen, with multiple
    cgroups exist in one system, we might want some of the cgroups's memory
    or tasks survived the reclaim and oom while there are other candidates.

    The "memory.low" and "memory.min" make that happen during reclaim, this
    "memory.priority" introduces a priority oom to meet above requirement
    in oom.

    The priority value is from 0 to 12, the higher number the higher priority.
    The priority is among siblings, it is not global priority, by this we can
    map these 13 priorities to the tens of thousands of memcgs.

    When oom happens it first chooses the lowest priority memcg as victim then
    uses the kernel default algorithm(see function oom_evaluate_task()) to select
    bad process from the victim memcg.

    For example::

     The following hierarchy:
                    root
                    /  \
                   A    B
                  / \  /  \
                 C   D E   F

     priority:
        A: 10, B: 8
        C: 5, D: 6, E: 7, F: 8

    When oom happens in root, it first iterates its two children A and B, and selects
    B as next iteration root since B's priority is lower than A, subsequent victim
    selection is limit in the B's subtree. E is selected as victim memcg finally, since
    its priority is lower than its sibling.

    This priority oom works both for memcg and global oom. For global oom the root is
    root memcg.

memory.use_priority_oom
=======================
    This file is used to enable/disable priority oom.

    Write "1" to enable the priority oom and "0" to disable it.
