#!/bin/bash

set -e

echo "======================================"
echo " KernelShield Runtime Preparation"
echo "======================================"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run this script using sudo."
    echo "Usage: sudo ./deployment/scripts/prepare-runtime.sh"
    exit 1
fi

echo "[1/4] Creating configuration directory..."
mkdir -p /etc/kernelshield

echo "[2/4] Creating log directory..."
mkdir -p /var/log/kernelshield

echo "[3/4] Creating runtime data directory..."
mkdir -p /var/lib/kernelshield

echo "[4/4] Creating deployment directory..."
mkdir -p /opt/kernelshield

chmod 755 /etc/kernelshield
chmod 755 /var/log/kernelshield
chmod 755 /var/lib/kernelshield
chmod 755 /opt/kernelshield

echo
echo "Created:"
echo "  /etc/kernelshield"
echo "  /var/log/kernelshield"
echo "  /var/lib/kernelshield"
echo "  /opt/kernelshield"

echo
echo "======================================"
echo " KernelShield runtime environment READY"
echo "======================================"
