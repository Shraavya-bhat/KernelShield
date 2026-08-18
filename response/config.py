"""
KernelShield Configuration
"""

# Never terminate these system-critical PIDs
PROTECTED_PIDS = [1, 2]

# Supported attack types
SUPPORTED_ATTACKS = [
    "reverse_shell",
    "privilege_escalation",
    "suspicious_process"
]
