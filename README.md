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
