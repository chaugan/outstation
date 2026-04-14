#!/usr/bin/env bash
# End-to-end smoke test for v1.1/v1.2 features:
#   1. Start a slow raw replay via POST /api/run
#   2. Poll /api/runs/:id and confirm live progress counters advance
#   3. Stop the run mid-flight via POST /api/runs/:id/stop
#   4. Verify final state is "stopped" with partial sent count
#   5. Fetch the gap histogram
#   6. Start a benchmark run against an unreachable target and verify
#      the benchmark-mode dispatch plumbing surfaces per-session errors
set -e
sleep 0.5

BASE=http://127.0.0.1:8080

echo "=== /api/status ==="
curl -s $BASE/api/status
echo
echo
echo "=== raw replay: slow run with mid-flight stop ==="
cat > /tmp/run_raw.json <<'JSON'
{
  "pcap": "/mnt/c/Users/chris/Downloads/iec104.pcap",
  "target_ip": "10.99.0.1",
  "target_mac": "02:00:00:00:aa:01",
  "bridge": "pcr_br0",
  "speed": 0.5,
  "realtime": true,
  "warmup_secs": 0,
  "mode": "raw"
}
JSON
RUN=$(curl -s -X POST $BASE/api/run -H 'Content-Type: application/json' --data-binary @/tmp/run_raw.json)
ID=$(echo "$RUN" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
echo "run id: $ID"

sleep 1.2
SNAP=$(curl -s $BASE/api/runs/$ID)
echo "-- after 1.2s --"
echo "$SNAP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('status        :', d['status'])
print('mode          :', d.get('mode'))
print('planned       :', d['planned'])
print('sent          :', d['sent'])
print('per_source    :', [(p['src_ip'], p['sent'], '/', p['planned']) for p in d['per_source_progress']])
print('throughput_tail:', d['throughput_history'][-5:] if d['throughput_history'] else [])
"

echo
echo "-- requesting stop --"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST $BASE/api/runs/$ID/stop
sleep 1.5
FINAL=$(curl -s $BASE/api/runs/$ID)
echo "-- after stop --"
echo "$FINAL" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('status        :', d['status'])
print('sent          :', d['sent'])
print('planned       :', d['planned'])
if d.get('report'):
    print('report.sent   :', d['report']['total_packets'])
    print('capture_path  :', d['report'].get('capture_path'))
"

echo
echo "=== gap histogram for run #$ID ==="
curl -s $BASE/api/runs/$ID/gaps | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('original sum:', sum(d['original']))
print('captured sum:', sum(d['captured']))
print('original    :', d['original'])
print('captured    :', d['captured'])
"

echo
echo "=== benchmark dispatch test (unreachable target) ==="
cat > /tmp/run_bench.json <<'JSON'
{
  "pcap": "/mnt/c/Users/chris/Downloads/iec104.pcap",
  "target_ip": "127.0.0.2",
  "target_mac": "",
  "bridge": "pcr_br0",
  "warmup_secs": 0,
  "mode": "benchmark",
  "target_port": 2404,
  "proto_name": "iec104",
  "concurrency": "all_at_once"
}
JSON
BRUN=$(curl -s -X POST $BASE/api/run -H 'Content-Type: application/json' --data-binary @/tmp/run_bench.json)
BID=$(echo "$BRUN" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
echo "benchmark run id: $BID"

# Poll until completed
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.5
  S=$(curl -s $BASE/api/runs/$BID | sed -n 's/.*"status":"\([a-z_]*\)".*/\1/p')
  echo "poll $i: $S"
  [[ "$S" == "completed" || "$S" == "failed" || "$S" == "stopped" ]] && break
done

echo
echo "=== benchmark final ==="
curl -s $BASE/api/runs/$BID | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('status              :', d['status'])
print('mode                :', d.get('mode'))
print('error               :', d.get('error'))
b = d.get('benchmark') or {}
print('sessions            :', len(b.get('per_session', [])))
print('total_messages_sent :', b.get('total_messages_sent'))
for s in b.get('per_session', []):
    print('  -', s['src_ip'], 'connected=', s['connected'], 'sent=', s['messages_sent'], 'error=', s.get('error'))
"
