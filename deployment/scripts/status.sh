#!/bin/bash

echo "======================================"
echo " KernelShield Deployment Status"
echo "======================================"

READY=1

check_dir() {
    if [ -d "$1" ]; then
        echo "[OK]      $2"
    else
        echo "[MISSING] $2"
        READY=0
    fi
}

echo
echo "SYSTEM"
echo "--------------------------------------"
echo "Host:   $(hostname)"
echo "Kernel: $(uname -r)"
echo "OS:     $(. /etc/os-release && echo "$PRETTY_NAME")"

echo
echo "eBPF"
echo "--------------------------------------"

if command -v bpftool >/dev/null 2>&1; then
    echo "[OK]      bpftool available"
else
    echo "[MISSING] bpftool"
    READY=0
fi

if [ -d /sys/fs/bpf ]; then
    echo "[OK]      BPF filesystem available"
else
    echo "[MISSING] BPF filesystem"
    READY=0
fi

echo
echo "CONTAINER RUNTIME"
echo "--------------------------------------"

if docker info >/dev/null 2>&1; then
    echo "[OK]      Docker daemon running"
else
    echo "[MISSING] Docker daemon unavailable"
    READY=0
fi

echo
echo "KERNELSHIELD RUNTIME"
echo "--------------------------------------"

check_dir /etc/kernelshield "Configuration directory"
check_dir /var/log/kernelshield "Logging directory"
check_dir /var/lib/kernelshield "State directory"
check_dir /opt/kernelshield "Application directory"

echo
echo "APPLICATION"
echo "--------------------------------------"

if [ -x /opt/kernelshield/kernelshield ]; then
    echo "[DEPLOYED] KernelShield executable"
else
    echo "[WAITING]  KernelShield executable not deployed"
fi

echo
echo "======================================"

if [ "$READY" -eq 1 ]; then
    echo "Infrastructure Status : READY"

    if [ -x /opt/kernelshield/kernelshield ]; then
        echo "Application Status    : DEPLOYED"
    else
        echo "Application Status    : WAITING FOR BUILD"
    fi
else
    echo "Infrastructure Status : NOT READY"
fi

echo "======================================"
