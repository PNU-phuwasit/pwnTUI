#!/bin/sh
for s in s_probe.py s_cyclic.py s_layout.py s_probe2.py s_probe3.py s_probe4.py s_pie.py s_hostile.py s_latency.py acceptance.py; do
  echo "############## $s"
  timeout 1500 python3 -u "$s" 2>&1 | grep -E '^(  !!|RESULT|FAILURES:| - \[)' || echo "  (clean)"
done
echo "############## real pty session"
timeout 200 python3 -u s_real.py 2>&1 | head -3
echo "############## DONE"
