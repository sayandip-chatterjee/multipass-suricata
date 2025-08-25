# 🛡️ Suricata on Multipass – Automated Setup Script  

This repository provides a **Python-based automation script** to deploy and configure **Suricata IDS/IPS** inside a **Multipass-managed Ubuntu VM**.  

The script is a Python conversion of a Bash automation flow and helps you quickly spin up a VM, install Suricata, configure it, and test detection capabilities.  

---

## 🚀 Features  
- Interactive **countdown timer** before critical steps.  
- Automated **Multipass installation & VM provisioning**.  
- Suricata installation and **systemd service configuration**.  
- Guided **Suricata YAML editing** for network interface & rule reloading.  
- Built-in **suricata-update** integration to fetch latest rule sources.  
- Test setup against [`testmynids.org`](http://testmynids.org/uid/index.html) to verify detection.  
- View Suricata logs (`fast.log`, `eve.json`) for alerts.  

---

## 🛠️ Requirements  
- Ubuntu (tested on **22.04+**)  
- **Python 3.8+**  
- **Multipass** installed (`snap install multipass`)  
- `jq` package (installed inside the VM automatically)  

---

## 📦 Installation & Usage  

Clone the repository and run the setup script:  

```bash
git clone https://github.com/sayandip-chatterjee/multipass-suricata.git
cd multipass-suricata/
python3 setup_suricata.py
```
ADDITIONAL NOTES:
```
sudo su
cd /var/lib/suricata/rules

after opening the directory you need to either create a new rule file or delete the suricata.rules file content and replace your own rules content.
If you create a new rule file then make sure it is present in the suricata.yaml configuration file
Then restart Suricata

cd /etc/suricata/rules

IMPORTANT COMMANDS:
sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/eve.json
sudo tail -f /var/log/suricata/suricata.log
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl start suricata.service
sudo systemctl status suricata.service
sudo systemctl stop suricata.service
sudo kill -usr2 $(pidof suricata)"
sudo nano /etc/suricata/suricata.yaml
sudo scapy
curl
sudo nano /var/lib/suricata/rules/suricata.rules
sudo nano /var/lib/suricata/rules/test.rules
tcpdump or wireshark
sudo python3 -m http.server 80

For starting a HTTPS server: (IGNORE for NOW)

1. Ruby-Script (I tested with Ruby 2.1.2.)

sudo nano https.rb

ruby -r webrick/https -e '
  WEBrick::HTTPServer.new(
    Port: 8000, DocumentRoot: ".",
    SSLEnable: true, SSLCertName: [%w[CN localhost]]).start'

sudo chmod 777 https.rb

./https.rb

https://localhost:8000
```
