#!/bin/bash

echo "======================================"
echo " KernelShield Environment Check"
echo "======================================"

ERRORS=0

check_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "[OK] $1 installed"
    else
        echo "[FAIL] $1 missing"
        ERRORS=$((ERRORS + 1))
    fi
}

echo
echo "[1] Checking Linux..."
if [ "$(uname -s)" = "Linux" ]; then
    echo "[OK] Linux detected"
else
    echo "[FAIL] KernelShield requires Linux"
    ERRORS=$((ERRORS + 1))
fi

echo
echo "[2] Kernel version:"
uname -r

echo
echo "[3] Checking required tools..."
check_tool git
check_tool gcc
check_tool clang
check_tool bpftool
check_tool python3
check_tool docker

echo
echo "[4] Checking eBPF filesystem..."
if [ -d /sys/fs/bpf ]; then
    echo "[OK] /sys/fs/bpf available"
else
    echo "[FAIL] /sys/fs/bpf unavailable"
    ERRORS=$((ERRORS + 1))
fi

echo
echo "[5] Checking Docker daemon..."
if docker info >/dev/null 2>&1; then
    echo "[OK] Docker daemon running"
else
    echo "[FAIL] Docker daemon unavailable"
    ERRORS=$((ERRORS + 1))
fi

echo
echo "[6] Checking KernelShield directories..."

for dir in src/ebpf src/collector src/detector; do
    if [ -d "$dir" ]; then
        echo "[OK] $dir"
    else
        echo "[FAIL] $dir missing"
        ERRORS=$((ERRORS + 1))
    fi
done

echo
echo "======================================"

if [ "$ERRORS" -eq 0 ]; then
    echo "KernelShield environment: READY"
    exit 0
else
    echo "KernelShield environment: NOT READY"
    echo "$ERRORS problem(s) detected."
    exit 1
fi
