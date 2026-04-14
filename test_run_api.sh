#!/usr/bin/env bash
set -e
sudo ip link del pcr_br0 2>/dev/null || true

cat > /tmp/run.json <<'JSON'
{"pcap":"/tmp/jitter_in.pcap","target_ip":"10.99.0.1","target_mac":"02:00:00:00:aa:01","bridge":"pcr_br0","realtime":true}
JSON

RUN=$(curl -s -X POST http://127.0.0.1:18080/api/run \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/run.json)
echo "run response: $RUN"
ID=$(echo "$RUN" | python3 -c "import json,sys;print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "$RUN" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
echo "run id: $ID"

for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.3
  STATE=$(curl -s "http://127.0.0.1:18080/api/runs/$ID")
  STATUS=$(echo "$STATE" | sed -n 's/.*"status":"\([a-z_]*\)".*/\1/p')
  echo "poll $i: $STATUS"
  if [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]]; then break; fi
done

echo
echo "=== final run state ==="
curl -s "http://127.0.0.1:18080/api/runs/$ID"
echo
