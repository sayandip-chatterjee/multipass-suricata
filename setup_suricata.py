#!/usr/bin/env python3

import subprocess
import time
import sys
import os


# Countdown function
def countdown(seconds):
    end_time = time.time() + seconds
    while time.time() < end_time:
        remaining = int(end_time - time.time())
        sys.stdout.write(
            "\r" + time.strftime("%H:%M:%S", time.gmtime(remaining))
        )
        sys.stdout.flush()
        time.sleep(0.1)
    print()


# Run shell commands
def run(cmd, capture_output=False, check=True, shell=True):
    print(f"\033[1;34m[+] Running:\033[0m {cmd}")
    return subprocess.run(
        cmd, shell=shell, text=True,
        capture_output=capture_output, check=check
    )


def main():
    print("\n\033[1;31mDisclaimer: Deactivate appedge or office network before proceeding...\033[0m")
    countdown(5)

    print("\n\033[1;31mInstalling multipass...\033[0m")
    run("sudo snap install multipass")
    countdown(5)

    run("sudo snap refresh")
    countdown(5)

    vmname = input("\n\033[1;31mPlease type a unique name for your VM instance:\033[0m ")

    run("sudo chmod a+w /var/snap/multipass/common/multipass_socket")
    countdown(5)

    run(f"multipass launch --name {vmname}")
    run(f"multipass exec {vmname} -- lsb_release -a")
    run("multipass list")
    run("multipass help")
    countdown(10)

    run(f"multipass start {vmname}")

    print("\n\033[1;31mInstalling Suricata...\033[0m")

    run(f"multipass exec {vmname} -- sudo add-apt-repository -y ppa:oisf/suricata-stable")
    run(f"multipass exec {vmname} -- sudo apt update && sudo apt install -y suricata")
    run(f"multipass exec {vmname} -- sudo systemctl enable suricata.service")
    run(f"multipass exec {vmname} -- sudo systemctl stop suricata.service")

    run(f"multipass exec {vmname} -- ip addr")
    run(f"multipass exec {vmname} -- ip -p -j route show default")

    print("\n\033[1;31mPlease note down the network interface named <dev> above.\033[0m")
    countdown(15)

    run(f"multipass exec {vmname} -- sudo nano /etc/suricata/suricata.yaml")

    print("\n\033[1;31mAdd these at the bottom of the suricata.yaml file:\033[0m")
    print("...\ndetect-engine:\n  - rule-reload: true\n")
    countdown(15)

    run(f"multipass exec {vmname} -- sudo nano /etc/suricata/suricata.yaml")

    print("\n\033[1;31mSince Rule Loading is enabled, use this command after adding new rules:\033[0m")
    print(f"multipass exec {vmname} -- sudo kill -usr2 $(pidof suricata)")
    countdown(15)

    run(f"multipass exec {vmname} -- sudo suricata-update")
    run(f"multipass exec {vmname} -- sudo suricata-update list-sources")

    print("\n\033[1;31mTo enable a custom source as listed above:\033[0m")
    print(f"multipass exec {vmname} -- sudo suricata-update enable-source tgreen/hunting")
    countdown(15)

    run(f"multipass exec {vmname} -- sudo suricata -T -c /etc/suricata/suricata.yaml -v")

    run(f"multipass exec {vmname} -- sudo systemctl start suricata.service")
    run(f"multipass exec {vmname} -- sudo systemctl status suricata.service")

    run(f"multipass exec {vmname} -- sudo apt install -y jq")
    countdown(5)

    run(f"multipass exec {vmname} -- curl http://testmynids.org/uid/index.html")

    countdown(5)
    run(f"multipass exec {vmname} -- cat /var/log/suricata/fast.log | grep 2100498", check=False)
    countdown(5)
    run(f"multipass exec {vmname} -- jq 'select(.alert .signature_id==2100498)' /var/log/suricata/eve.json", check=False)
    countdown(5)

    print("\n\033[1;31mIf you can visualize alerts in both fast.log and eve.json, Suricata setup was successful!\033[0m")
    countdown(5)
    print("\n\033[1;33mNow starting a shell session with your VM... Let's go!\033[0m")
    countdown(5)

    os.system(f"multipass shell {vmname}")


if __name__ == "__main__":
    main()
