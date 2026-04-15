#!/usr/bin/env bash
set -e
sleep 0.5

cat > /tmp/run2.json <<'JSON'
{"pcap":"/mnt/c/Users/chris/Downloads/iec104.pcap","target_ip":"10.99.0.1","target_mac":"02:00:00:00:aa:01","bridge":"pcr_br0","realtime":true,"top_speed":true,"warmup_secs":0}
JSON

RUN=$(curl -s -X POST http://127.0.0.1:8080/api/run \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/run2.json)
echo "response: $RUN"
ID=$(echo "$RUN" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')

for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.3
  STATE=$(curl -s "http://127.0.0.1:8080/api/runs/$ID")
  STATUS=$(echo "$STATE" | sed -n 's/.*"status":"\([a-z_]*\)".*/\1/p')
  echo "poll $i: $STATUS"
  [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
done

echo
echo "=== final state (excerpt) ==="
curl -s "http://127.0.0.1:8080/api/runs/$ID" | python3 -c "
import json, sys
r = json.load(sys.stdin)
rep = r.get('report') or {}
print('status          :', r['status'])
print('error           :', r.get('error'))
print('total_packets   :', rep.get('total_packets'))
print('captured_packets:', rep.get('captured_packets'))
print('captured_bytes  :', rep.get('captured_bytes'))
print('capture_path    :', rep.get('capture_path'))
"

echo
echo "=== download test ==="
curl -s -D - -o /tmp/downloaded.pcap "http://127.0.0.1:8080/api/runs/$ID/download" | head -5
echo "downloaded size: $(stat -c %s /tmp/downloaded.pcap) bytes"
echo
echo "=== inspect downloaded pcap ==="
cd ~/projects/outstation
./target/release/pcapinspect /tmp/downloaded.pcap 2>/dev/null || ./target/debug/pcapinspect /tmp/downloaded.pcap
