#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate

echo "Ожидание загрузки X64 VM (TCG ~15-20 мин)"


MAX_WAIT=1800
INTERVAL=30
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    SOCK=$(ls /tmp/vm_sandbox/*x64*agent.sock 2>/dev/null | head -1)

    if [ -n "$SOCK" ]; then
        RESULT=$(python3 -c "
import socket
import json
try:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect('$SOCK')
    sock.send((json.dumps({'command': 'ping'}) + '\n').encode())
    resp = sock.recv(4096).decode().split('\n')[0]
    data = json.loads(resp)
    if data.get('success'):
        print('OK')
    else:
        print('FAIL')
    sock.close()
except:
    print('WAIT')
" 2>/dev/null)

        if [ "$RESULT" = "OK" ]; then
            echo ""
            echo "X64 Agent готов!"
            echo ""

            echo "Создание pool_ready снэпшота..."
            MON_SOCK=$(ls /tmp/vm_sandbox/*x64*monitor.sock 2>/dev/null | head -1)

            python3 -c "
import socket
import json
import time

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(120)
sock.connect('$MON_SOCK')
sock.recv(4096)
sock.send(b'{\"execute\": \"qmp_capabilities\"}\\n')
sock.recv(4096)

sock.send(b'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"delvm pool_ready\"}}\\n')
time.sleep(1)
sock.recv(4096)

print('Saving snapshot...')
sock.send(b'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"savevm pool_ready\"}}\\n')
time.sleep(10)


sock.send(b'{\"execute\": \"cont\"}\\n')
time.sleep(2)


sock.send(b'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"info snapshots\"}}\\n')
resp = sock.recv(8192)
result = json.loads(resp.decode())
print(result.get('return', 'No info'))
sock.close()
"

            exit 0
        fi
    fi

    MINS=$((ELAPSED / 60))
    echo "[$MINS мин]"
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

exit 1
