
import subprocess


def block_ip(ip):

    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            check=True
        )

        print(f"[FIREWALL] Blocked connection to {ip}")
        return True

    except subprocess.CalledProcessError:
        print(f"[FIREWALL] Failed to block {ip}")
        return False
