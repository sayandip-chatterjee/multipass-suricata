#!/usr/bin/env python3

import os, subprocess, time, sys

def progress_bar(duration, prefix="Progress", length=30):
    """
    Displays a progress bar in the terminal.
    
    :param duration: total time in seconds for the progress bar
    :param prefix: text before the progress bar
    :param length: length of the bar in characters
    """
    for i in range(length + 1):
        percent = i / length
        bar = "#" * i + "-" * (length - i)
        sys.stdout.write(f"\r{prefix}: [{bar}] {percent*100:.0f}%")
        sys.stdout.flush()
        time.sleep(duration / length)
    print()

def wait_for_enter(message="Press ENTER to continue..."):
    input(f"\033[1;33m{message}\033[0m")

# Run shell commands
def run(cmd, capture_output=False, check=True, shell=True):
    print(f"\033[1;34m[+] Running:\033[0m {cmd}")
    return subprocess.run(
        cmd, shell=shell, text=True,
        capture_output=capture_output, check=check
    )

def main():
    print("\n\033[1;31mDisclaimer: Deactivate any SECURED network before proceeding...\033[0m")
    wait_for_enter("Press ENTER to continue...")

    print("\n\033[1;31mInstalling multipass...\033[0m")
    run("sudo snap install multipass")
    wait_for_enter("Press ENTER to continue...")

    run("sudo snap refresh")
    wait_for_enter("Press ENTER to continue...")

    vmname = input("\n\033[1;31mPlease type a unique name for your VM instance:\033[0m ")

    run("sudo chmod a+w /var/snap/multipass/common/multipass_socket")
    wait_for_enter("Press ENTER to continue...")

    run(f"multipass launch --name {vmname}")
    run(f"multipass exec {vmname} -- lsb_release -a")
    run("multipass list")
    run("multipass help")
    wait_for_enter("Press ENTER to continue...")

    run(f"multipass start {vmname}")

    print("\n\033[1;31mInstalling Suricata...\033[0m")

    """
    If system hangs after showing this you need to:
    1. Ctrl + C (exit)
    2. multipass delete $vmname ; multipass purge
    """

    run(f"multipass exec {vmname} -- sudo add-apt-repository -y ppa:oisf/suricata-stable")
    run(f"multipass exec {vmname} -- sudo apt install -y suricata")
    run(f"multipass exec {vmname} -- sudo systemctl enable suricata.service")
    run(f"multipass exec {vmname} -- sudo systemctl stop suricata.service")

    run(f"multipass exec {vmname} -- ip addr")
    run(f"multipass exec {vmname} -- ip -p -j route show default")

    print("\n\033[1;31mPlease note down the network interface named <dev> above.\033[0m")
    print("\n\033[1;33mPlease Read Below Paragraph\033[0m")
    print("Scroll through the file until you come to a line that reads af-packet: around line 660.\n \
    If you are using nano you can also go to the line directly by entering CTRL+_ and typing the line number. \n \
    Below that line is the default interface that Suricata will use to inspect traffic.\n \
    Edit the line to match your interface named <dev>:\n")
    wait_for_enter("Press ENTER to continue...")

    run(f"multipass exec {vmname} -- sudo nano /etc/suricata/suricata.yaml")

    print("\n\033[1;31mAdd these at the bottom of the suricata.yaml file:\033[0m")
    print("\ndetect-engine:\n  - rule-reload: true\n")
    wait_for_enter("Press ENTER to continue...")

    run(f"multipass exec {vmname} -- sudo nano /etc/suricata/suricata.yaml")

    print("\n\033[1;31mSince Rule Loading is enabled, use this command after adding new rules:\033[0m")
    print(f"multipass exec {vmname} -- sudo kill -usr2 $(pidof suricata)")
    wait_for_enter("Press ENTER to continue...")

    run(f"multipass exec {vmname} -- sudo suricata-update")
    run(f"multipass exec {vmname} -- sudo suricata-update list-sources")

    print("\n\033[1;31mTo enable a custome source as listed above, execute the below command\033[0m")
    print(f"multipass exec {vmname} -- sudo suricata-update enable-source tgreen/hunting")
    wait_for_enter("Press ENTER to continue...")

    run(f"multipass exec {vmname} -- sudo suricata -T -c /etc/suricata/suricata.yaml -v")

    run(f"multipass exec {vmname} -- sudo systemctl start suricata.service")
    run(f"multipass exec {vmname} -- sudo systemctl status suricata.service")
    progress_bar(60, prefix="Waiting for Suricata to initialize...")

    run(f"multipass exec {vmname} -- curl http://testmynids.org/uid/index.html")

    wait_for_enter("Press ENTER to continue...")
    run(f"multipass exec {vmname} -- sudo grep 2100498 /var/log/suricata/fast.log", check=False)
    wait_for_enter("Press ENTER to continue...")
    run(f"multipass exec {vmname} -- sudo jq 'select(.alert .signature_id==2100498)' /var/log/suricata/eve.json", check=False)
    wait_for_enter("Press ENTER to continue...")

    print("\n\033[1;31mIf you can visualize alerts in both fast.log and eve.json, Suricata setup was successful!\033[0m")
    wait_for_enter("Press ENTER to continue...")

    print("\n\033[1;31mIf you CANNOT visualize alerts in both fast.log and eve.json, Suricata setup FAILED! So exec into your vm and then run the curl command used here in line 87 and check for the log in fast.log and eve.json\033[0m")
    wait_for_enter("Press ENTER to continue...")
    print("\n\033[1;33mNow starting a shell session with your VM... Let's go!\033[0m")
    wait_for_enter("Press ENTER to continue...")

    os.system(f"multipass shell {vmname}")


if __name__ == "__main__":
    main()
