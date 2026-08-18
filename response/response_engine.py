import json
from process_killer import terminate_process
from logger import write_log
from config import PROTECTED_PIDS
from firewall import block_ip

def decide_response(attack_type):

    if attack_type == "reverse_shell":
        return "Terminate Process"

    elif attack_type == "privilege_escalation":
        return "Kill Process + Alert"

    elif attack_type == "suspicious_process":
        return "Terminate Process"

    else:
        return "No Action"


def receive_detection():

    with open("detection.json", "r") as file:
        detection = json.load(file)

    attack_type = detection["attack_type"]
    pid = detection["pid"]

    has_network = detection.get("has_network", 0)
    destination_ip = detection.get("destination_ip", "")
    destination_port = detection.get("destination_port", 0)

    action = decide_response(attack_type)

    print("========== KernelShield ==========")
    print(f"Attack Type : {attack_type}")
    print(f"PID         : {pid}")
    print(f"Action      : {action}")

    status = "NOT EXECUTED"

    if pid in PROTECTED_PIDS:

        print("[WARNING] Protected system process. Response cancelled.")

        status = "BLOCKED"

    elif action == "Terminate Process":

        success = terminate_process(pid)

        if success:
            status = "SUCCESS"
        else:
            status = "FAILED"

    if has_network and destination_ip:

        print(f"[NETWORK] Destination detected: {destination_ip}:{destination_port}")

        firewall_success = block_ip(destination_ip)

        if firewall_success:
            print("[NETWORK] Connection mitigation: SUCCESS")
        else:
            print("[NETWORK] Connection mitigation: FAILED")

    write_log(
        attack_type,
        pid,
        action,
        status
    )

    print(f"Status      : {status}")
    print("==================================")
def main():
    receive_detection()


if __name__ == "__main__":
    main()
