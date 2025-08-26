# 🛡️ Suricata on Multipass – Automated Setup Script  

This repository provides a **Python-based automation script** to deploy and configure **Suricata IDS/IPS** inside a **Multipass-managed Ubuntu VM**.

---

## 🖥️ About Suricata and Multipass  

**[Suricata](https://suricata.io/)** is a high-performance, open-source **Intrusion Detection and Prevention System (IDS/IPS)** capable of:  

- Real-time network traffic monitoring and analysis  
- Signature-based and anomaly-based threat detection  
- Deep Packet Inspection (DPI) and protocol analysis  
- Integration with logging formats like `EVE JSON` for advanced dashboards  

Suricata comes with **many advanced features**, including:  

- Multi-threading for high throughput  
- Automatic rule updates via `suricata-update`  
- AF_PACKET for high-speed network capture  
- Customizable rule sets for tailored detection  

More features: [https://suricata.io/features/all-features/](https://suricata.io/features/all-features/)  

**[Multipass](https://multipass.run/)** is a lightweight, cross-platform tool for managing **Ubuntu virtual machines**. It allows you to:  

- Rapidly spin up disposable VMs for testing or development  
- Manage multiple VM instances with simple commands (`launch`, `exec`, `shell`)  
- Run complex software in isolated environments without affecting the host  
- Experiment with services like Suricata safely  

### 🔗 Why use them together  

Using **Suricata inside a Multipass VM** allows you to:  

- Safely experiment with IDS/IPS configurations without risking your host or office network  
- Quickly spin up test environments for learning or proof-of-concept detection rules  
- Recreate different network scenarios, test rule updates, and inspect logs in a fully isolated VM  
- Automate setup and configuration for consistent, reproducible environments  

---

## 🚀 Features  
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

---

## 📦 Installation & Usage  

Clone the repository and run the setup script:  

```bash
git clone https://github.com/sayandip-chatterjee/multipass-suricata.git
cd multipass-suricata/
python3 setup_suricata.py
```

ADDITIONAL NOTES:

| Action / Topic | Command / Path / Notes |
|----------------|----------------------|
| Enter SuperUser | `sudo su` |
| Default rules directory | `/var/lib/suricata/rules` |
| Log / alert tracking | `/var/log/suricata/fast.log` <br> `/var/log/suricata/eve.json` |
| Track Suricata logs | `/var/log/suricata/suricata.log` |
| Test, load, validate Suricata | `sudo suricata -T -c /etc/suricata/suricata.yaml -v` |
| Restart signal | `sudo kill -usr2 $(pidof suricata)` |
| Suricata config | `/etc/suricata/suricata.yaml` |
| Systemctl commands | `sudo systemctl start suricata.service` <br> `sudo systemctl status suricata.service` <br> `sudo systemctl stop suricata.service` |
| Start a HTTP server | `sudo python3 -m http.server 80` -> Open in browser http://localhost:80 |
| Start a HTTPS server | `sudo ruby -r webrick/https -e "WEBrick::HTTPServer.new(Port: 8000, DocumentRoot: '.', SSLEnable: true, SSLCertName: [%w[CN localhost]]).start"` -> Open in browser https://localhost:8000|
| Editing / adding rules | After opening `/var/lib/suricata/rules`, either create a new rule file or delete `suricata.rules` content and replace with your own rules. Ensure the file is referenced in `suricata.yaml`, then restart Suricata. |




