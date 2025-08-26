#!/usr/bin/env python3

import shutil, sys, subprocess, platform, time, os

SYSTEM = platform.system().lower()
IS_WSL = "microsoft" in platform.uname().release.lower()

if SYSTEM == "windows":
    MULTIPASS = "multipass.exe"
else:
    MULTIPASS = "multipass"

def run(cmd, check=True, shell=True):
    print(f"\033[1;34m[+] Running:\033[0m {cmd}")
    return subprocess.run(cmd, shell=shell, text=True, check=check)

def check_multipass():
    """Verify multipass binary exists, else try to install."""
    if shutil.which(MULTIPASS) is None:
        print(f"\033[1;31m[!] {MULTIPASS} not found in PATH.\033[0m")

        if SYSTEM == "windows":
            print("\033[1;33m[>] Attempting automatic Multipass install on Windows...\033[0m")

            try:
                # Use winget (Windows Package Manager)
                run("winget install --id Canonical.Multipass -e --accept-source-agreements --accept-package-agreements")
                print("\n\033[1;32m[✓] Multipass installed successfully.\033[0m")
            except Exception as e:
                print("\033[1;31m[!] Automatic install failed. Please install manually:\033[0m")
                print("➡ https://multipass.run/download/windows")
                sys.exit(1)

        elif SYSTEM == "linux" and not IS_WSL:
            print("\033[1;33m[>] Installing Multipass via snap...\033[0m")
            try:
                run("sudo snap install multipass")
                run("sudo snap refresh")
                run("sudo chmod a+w /var/snap/multipass/common/multipass_socket", check=False)
                print("\n\033[1;32m[✓] Multipass installed successfully.\033[0m")
            except Exception:
                print("\033[1;31m[!] Failed to install multipass automatically.\033[0m")
                print("➡ Please install manually: https://multipass.run")
                sys.exit(1)

        elif IS_WSL:
            print("\033[1;31m[!] WSL detected. Multipass usually does not work in nested virtualization.\033[0m")
            print("➡ Please run the script on native Linux or Windows instead.")
            sys.exit(1)
    else:
        print(f"\033[1;32m[✓] Found {MULTIPASS} in PATH.\033[0m")

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

def run(cmd, capture_output=False, check=True, shell=True):
    print(f"\033[1;34m[+] Running:\033[0m {cmd}")
    return subprocess.run(
        cmd, shell=shell, text=True,
        capture_output=capture_output, check=check
    )

def main():
    print("\n\033[1;31mDisclaimer: Deactivate any SECURED network before proceeding...\033[0m")
    wait_for_enter("Press ENTER to continue...")

    check_multipass()

    vmname = input("\n\033[1;31mPlease type a unique name for your VM instance:\033[0m ")

    run(f"{MULTIPASS} launch --name {vmname}")
    run(f"{MULTIPASS} exec {vmname} -- lsb_release -a")
    run(f"{MULTIPASS} list")
    run(f"{MULTIPASS} help")
    wait_for_enter()

    run(f"{MULTIPASS} start {vmname}")

    print("\n\033[1;31mInstalling Suricata...\033[0m")

    """
    If system hangs after showing this you need to:
    1. Ctrl + C (exit)
    2. multipass delete $vmname ; multipass purge
    """
    run(f"{MULTIPASS} exec {vmname} -- sudo add-apt-repository -y ppa:oisf/suricata-stable")
    run(f"{MULTIPASS} exec {vmname} -- sudo apt install -y suricata")
    run(f"{MULTIPASS} exec {vmname} -- sudo systemctl enable suricata.service")
    run(f"{MULTIPASS} exec {vmname} -- sudo systemctl stop suricata.service")

    run(f"{MULTIPASS} exec {vmname} -- ip addr")
    run(f"{MULTIPASS} exec {vmname} -- ip -p -j route show default")

    print("\n\033[1;31mPlease note down the network interface named <dev> above.\033[0m")
    print("\n\033[1;33mPlease Read Below Paragraph\033[0m")
    print("Scroll through the file until you come to a line that reads af-packet: around line 660.\n \
    If you are using nano you can also go to the line directly by entering CTRL+_ and typing the line number. \n \
    Below that line is the default interface that Suricata will use to inspect traffic.\n \
    Edit the line to match your interface named <dev>:\n")
    wait_for_enter()

    run(f"{MULTIPASS} exec {vmname} -- sudo nano /etc/suricata/suricata.yaml")

    print("\n\033[1;31mAdd these at the bottom of the suricata.yaml file:\033[0m")
    print("\ndetect-engine:\n  - rule-reload: true\n")
    wait_for_enter()

    run(f"{MULTIPASS} exec {vmname} -- sudo nano /etc/suricata/suricata.yaml")

    print("\n\033[1;31mSince Rule Loading is enabled, use this after adding new rules:\033[0m")
    print(f"{MULTIPASS} exec {vmname} -- sudo kill -usr2 $(pidof suricata)")
    wait_for_enter()

    run(f"{MULTIPASS} exec {vmname} -- sudo suricata-update")
    run(f"{MULTIPASS} exec {vmname} -- sudo suricata-update list-sources")

    print("\n\033[1;31mTo enable a custom source as listed above:\033[0m")
    print(f"{MULTIPASS} exec {vmname} -- sudo suricata-update enable-source tgreen/hunting")
    wait_for_enter()

    run(f"{MULTIPASS} exec {vmname} -- sudo suricata -T -c /etc/suricata/suricata.yaml -v")

    run(f"{MULTIPASS} exec {vmname} -- sudo systemctl restart suricata.service")
    run(f"{MULTIPASS} exec {vmname} -- sudo systemctl status suricata.service")
    progress_bar(60, prefix="Waiting for Suricata to initialize...")

    run(f"{MULTIPASS} exec {vmname} -- curl http://testmynids.org/uid/index.html")

    wait_for_enter()
    run(f"{MULTIPASS} exec {vmname} -- sudo grep 2100498 /var/log/suricata/fast.log", check=False)
    wait_for_enter()
    run(f"""{MULTIPASS} exec {vmname} -- sudo jq 'select(.alert.signature_id==2100498)' /var/log/suricata/eve.json""", check=False)
    wait_for_enter()

    print("\n\033[1;31mIf you see alerts in both fast.log and eve.json, Suricata setup was successful!\033[0m")
    wait_for_enter()

    print("\n\033[1;31mIf NOT, run curl inside VM and check logs as done in lines after progress_bar above manually.\033[0m")
    wait_for_enter()
    print("\n\033[1;33mNow starting a shell session with your VM... Let's go!\033[0m")
    wait_for_enter()

    os.system(f"{MULTIPASS} shell {vmname}")


if __name__ == "__main__":
    main()
