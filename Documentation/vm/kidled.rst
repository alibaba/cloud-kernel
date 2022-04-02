.. SPDX-License-Identifier: GPL-2.0+

======
kidled
======

Introduction
============

kidled uses a kernel thread to scan the pages on LRU list, and supports to
output statistics for each memory cgroup (process is not supported yet).
kidled scans pages round to round indexed by pfn, and will try to finish each
round in a fixed duration which is named as scan period. Of course, users can
set the scan period whose unit is seconds. Each page has an attribute named
as 'idle age', which represents how long the page is kept in idle state, the
age's unit is in one scan period. The idle aging information (field) consumes
one byte, which is stored in dynamically allocated array, tied with the NUMA
node or flags field of page descriptor (struct page). So the maximal age is
255. kidled eventually shows the histogram statistics through memory cgroup
files (``memory.idle_page_stats``). The statistics could be used to evaluate
the working-set size of that memory cgroup or the hierarchy.

Note: The implementation of kidled had referred to Michel Lespinasse's patch:
https://lore.kernel.org/lkml/20110922161448.91a2e2b2.akpm@google.com/T/
Thanks for Michel Lespinasse's idea about page age and buckets!

Usage
=====

There are two sysfs files and two memory cgroup file, exported by kidled.
Here are their functions:

* ``/sys/kernel/mm/kidled/scan_period_in_seconds``

  It controls the scan period for the kernel thread to do the scanning.
  Higher resolution will be achieved with smaller value, but more CPU
  cycles will be consumed to do the scanning. The scanning won't be
  issued if 0 is set for the parameter and it's default setting. Writing
  to the file clears all statistics collected previously, even the scan
  period isn't changed.

.. note::
   A rare race exists! ``scan_period_in_seconds`` is only visible thing to
   users. duration and sequence number are internal representation for
   developers, and they'd better not be seen by users to avoid be confused.
   When user updates ``scan_period_in_seconds`` file, the sequence number
   is increased and the duration is updated sychronously, as below figure
   shows:

        OP           |       VALUE OF SCAN_PERIOD
   Initial value     | seq = 0,     duration = 0
   user update 120s  | seq = 1,     duration = 120 <---- last value kidled sees
   user update 120s  | seq = 2,     duration = 120 ---+
   ....              |                                | kidled may miss these
   ....              |                                | updates because busy
   user update 300s  | seq = 65536, duration = 300    |
   user update 300s  | seq = 0,     duration = 300 ---+
   user update 120s  | seq = 1,     duration = 120 <---- next value kidled sees

   The race happens when ``scan_period_in_seconds`` is updated very fast in a
   very short period of time and kidled misses just 65536 * N (N = 1,2,3...)
   updates and the duration keeps the same. kidled won't clear previous
   statistics, but it won't be very odd due to the duration are the same at
   least.

* ``memory.idle_page_stats.local`` (memory cgroup v1/v2)

  It shows histogram of idle statistics for the corresponding memory cgroup.

* ``memory.idle_page_stats`` (memory cgroup v1/v2)

  It shows histogram of accumulated idle statistics for the corresponding
  memory cgroup.

  ``memory.idle_page_stats.local`` and ``memory.idle_page_stats`` share the
  same output format, as shown below.

  ----------------------------- snapshot start -----------------------------
  # version: 1.0
  # scans: 1380
  # scan_period_in_seconds: 120
  # buckets: 1,2,5,15,30,60,120,240
  #
  #   _-----=> clean/dirty
  #  / _----=> swap/file
  # | / _---=> evict/unevict
  # || / _--=> inactive/active
  # ||| /
  # ||||              [1,2)          [2,5)         [5,15)        [15,30)        [30,60)       [60,120)      [120,240)     [240,+inf)
      csei                  0              0              0              0              0              0              0              0
      dsei                  0              0         442368          49152              0          49152         212992        7741440
      cfei               4096         233472        1171456        1032192          28672          65536         122880      147550208
      dfei                  0              0           4096          20480           4096              0          12288          12288
      csui                  0              0              0              0              0              0              0              0
      dsui                  0              0              0              0              0              0              0              0
      cfui                  0              0              0              0              0              0              0              0
      dfui                  0              0              0              0              0              0              0              0
      csea              77824         331776        1216512        1069056         217088         372736         327680       33284096
      dsea                  0              0              0              0              0              0              0         139264
      cfea               4096          57344         606208       13144064          53248         135168        1683456       48357376
      dfea                  0              0              0              0              0              0              0              0
      csua                  0              0              0              0              0              0              0              0
      dsua                  0              0              0              0              0              0              0              0
      cfua                  0              0              0              0              0              0              0              0
      dfua                  0              0              0              0              0              0              0              0
  ----------------------------- snapshot end -----------------------------

  ``scans`` means how many rounds current cgroup has been scanned.
  ``scan_period_in_seconds`` means kidled will take how long to finish
  one round. ``buckets`` is to allow scripts parsing easily. The table
  shows how many bytes are in idle state, the row is indexed by idle
  type and column is indexed by idle ages.

  e.g. it shows 331776 bytes are idle at column ``[2,5)`` and row ``csea``,
  ``csea`` means the pages are clean && swappable && evictable && active,
  ``[2,5)`` means pages keep idle at least 240 seconds and less than 600
  seconds (get them by [2, 5) * scan_period_in_seconds). The last column
  ``[240,+inf)`` means pages keep idle for a long time, greater than 28800
  seconds.

  Each memory cgroup can have its own histogram sampling different from
  others by echo a monotonically increasing array to either
  ``memory.idle_page_stats.local`` or ``memory.idle_page_stats``, each number
  should be less than 256 and the write operation will clear previous stats
  even buckets have not been changed. The number of bucket values must be
  less or equal than 8. The default setting is "1,2,5,15,30,60,120,240".
  Null bucket values (i.e. a null string) means no need account to current
  memcg (NOTE it will still account to parent memcg if parent memcg exists
  and has non-null buckets), non-accounting's snapshot looks like below:

  ----------------------------- snapshot start -----------------------------
  $ sudo bash -c "echo '' > /sys/fs/cgroup/memory/test/memory.idle_page_stats"
  $ cat /sys/fs/cgroup/memory/test/memory.idle_page_stats
  # version: 1.0
  # scans: 0
  # scan_period_in_seconds: 1
  # buckets: no valid bucket available
  ----------------------------- snapshot end -----------------------------
