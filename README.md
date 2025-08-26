# 🛡️ Suricata on Multipass – Automated Setup Script  

This repository provides a **Python-based automation script** to deploy and configure **Suricata IDS/IPS** inside a **Multipass-managed Ubuntu VM**.

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
| Start a HTTP server | `sudo python3 -m http.server 80` |
| Start a HTTPS server | 1. `sudo nano https.rb` <br> 2. `ruby -r webrick/https -e 'WEBrick::HTTPServer.new(Port: 8000, DocumentRoot: ".", SSLEnable: true, SSLCertName: [%w[CN localhost]]).start'` <br> 3. `sudo chmod 777 https.rb` <br> 4. `./https.rb` <br> 5. Access via `https://localhost:8000` |
| Editing / adding rules | After opening `/var/lib/suricata/rules`, either create a new rule file or delete `suricata.rules` content and replace with your own rules. Ensure the file is referenced in `suricata.yaml`, then restart Suricata. |



