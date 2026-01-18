#!/bin/bash

cd "$(dirname "$0")"

source venv/bin/activate

if [ ! -w /dev/kvm ]; then
    echo "⚠️  No KVM access, trying sg kvm..."
    exec sg kvm -c "$0"
fi

echo "=================================================="
echo "🚀 Malware Analysis Bot"
echo "=================================================="
echo ""
echo "KVM access: ✅"
echo "Python: $(python3 --version)"
echo ""

exec python3 tgbot.py
