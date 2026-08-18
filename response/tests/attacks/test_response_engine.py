import subprocess
import json
import os
import sys
import time


RESPONSE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

sys.path.insert(0, RESPONSE_DIR)


TEST_IP = "203.0.113.10"
DETECTION_FILE = os.path.join(RESPONSE_DIR, "detection.json")


def run_test():

    print("==============================================")
    print(" KernelShield End-to-End Response Test")
    print("==============================================")

    # Create a harmless test process
    process = subprocess.Popen(["sleep", "60"])
    pid = process.pid

    print(f"Test Process PID : {pid}")

    # Create a controlled detection alert
    detection = {
        "schema_version": 1,
        "pid": pid,
        "ppid": os.getpid(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "process_name": "sleep",
        "parent_name": "python3",
        "attack_type": "reverse_shell",
        "alert_type": "behavioral",
        "severity": "HIGH",
        "reason": "Controlled test alert",
        "mitre_technique": "T1059",
        "has_network": 1,
        "destination_ip": TEST_IP,
        "destination_port": 4444,
        "event_count": 1
    }

    # Save the temporary detection
    with open(DETECTION_FILE, "w") as file:
        json.dump(detection, file, indent=4)

    time.sleep(1)

    # Run the actual response engine
    result = subprocess.run(
        ["python3", "response_engine.py"],
        cwd=RESPONSE_DIR,
        capture_output=True,
        text=True
    )

    print(result.stdout)

    # Check whether the process was terminated
    process_check = subprocess.run(
    ["ps", "-p", str(pid)],
    capture_output=True,
    text=True
    )

    process_terminated = "SUCCESS] Process" in result.stdout

    # Check firewall rule
    firewall_check = subprocess.run(
        ["sudo", "iptables", "-L", "OUTPUT", "-n"],
        capture_output=True,
        text=True
    )

    firewall_blocked = TEST_IP in firewall_check.stdout

    # Cleanup firewall rule
    subprocess.run(
        ["sudo", "iptables", "-D", "OUTPUT", "-d", TEST_IP, "-j", "DROP"],
        check=False
    )

    # Final result
    if process_terminated and firewall_blocked:
        print("Expected Result : Process terminated + IP blocked")
        print("Actual Result   : Process terminated + IP blocked")
        print("TEST RESULT     : PASS")
    else:
        print("Expected Result : Process terminated + IP blocked")
        print(
            f"Actual Result   : "
            f"Process terminated = {process_terminated}, "
            f"IP blocked = {firewall_blocked}"
        )
        print("TEST RESULT     : FAIL")

    print("==============================================")


if __name__ == "__main__":
    run_test()
