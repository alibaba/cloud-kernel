.. _memcg_zombie_reaper:

===================
Memcg Zombie Reaper
===================

After memcg was deleted, page caches still reference to this memcg
causing large number of dead (zombie) memcgs in the system. Then it
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
