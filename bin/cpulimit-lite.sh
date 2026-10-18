#!/bin/bash
# cpulimit-lite.sh — built-in CPU-cap FALLBACK for when the native `cpulimit` binary isn't installed
# (repo/network unavailable). Caps PID $1 to $2 %CPU for $3 seconds by SIGSTOP/SIGCONT duty-cycling
# (the same technique cpulimit uses), then ALWAYS leaves the process running.
#
# SAFETY: a trap guarantees the target is resumed (SIGCONT) on ANY exit path, so it can never be left
# stopped even if this script is killed. The Cooler's revert also SIGCONTs as belt-and-suspenders.
#
# Usage: cpulimit-lite.sh <pid> <cap-percent 1..99> <duration-seconds> [start-time]
#   start-time: the kernel start time of the PID (field 22 of /proc/<pid>/stat) recorded by the caller. The PID
#   number is reused after the target exits; this is not - the loop stops the moment it no longer matches, so a
#   process that inherited the number is never frozen.
pid="${1:-0}"; cap="${2:-50}"; dur="${3:-900}"; want="${4:-}"
case "$pid" in ''|*[!0-9]*) exit 1;; esac
[ "$pid" -gt 1 ] || exit 1
case "$cap" in ''|*[!0-9]*) cap=50;; esac
[ "$cap" -ge 100 ] && exit 0            # no cap requested
[ "$cap" -lt 1 ] && cap=1
case "$dur" in ''|*[!0-9]*) dur=900;; esac

same() { [ -z "$want" ] || [ "$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | awk '{print $20}')" = "$want" ]; }
same || exit 0
trap 'same && kill -CONT "$pid" 2>/dev/null; exit 0' EXIT INT TERM HUP

period="0.10"                            # 100 ms scheduling slice
on=$(awk "BEGIN{printf \"%.3f\", $period*$cap/100}")
off=$(awk "BEGIN{printf \"%.3f\", $period-($period*$cap/100)}")
end=$(( $(date +%s) + dur ))

while [ "$(date +%s)" -lt "$end" ]; do
  kill -0 "$pid" 2>/dev/null || exit 0   # target gone → trap CONTs (harmless) and exits
  same || exit 0                          # the number now belongs to another process → stop at once
  kill -CONT "$pid" 2>/dev/null; sleep "$on"
  kill -STOP "$pid" 2>/dev/null; sleep "$off"
done
# loop finished → trap fires on EXIT → SIGCONT (process left running)
