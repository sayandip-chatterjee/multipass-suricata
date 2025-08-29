# 📘 Suricata Rules Guide

## 🔹 What are Suricata Rules?
Suricata rules are **signatures** that define how Suricata detects suspicious or malicious traffic.  
They specify:  
- **Which traffic to inspect** (protocol, IPs, ports, direction)  
- **What to look for** (patterns, fields, payloads)  
- **What to do when matched** (alert, drop, reject, pass)  

---

## 🔹 Rule Structure
A typical Suricata rule looks like this:

```suricata
alert tcp any any -> 192.168.1.10 80 (msg:"Possible attack"; content:"badstring"; sid:100001; rev:1;)
```

**Breakdown:**
- **Action**: `alert` → generate an alert  
- **Protocol**: `tcp`  
- **Source**: `any any` → any IP, any port  
- **Direction**: `->` → from source to destination  
- **Destination**: `192.168.1.10 80` → IP and port  
- **Options**: inside parentheses  
  - `msg` → log message  
  - `content` → pattern to search in payload  
  - `sid` → signature ID  
  - `rev` → revision number  

---

## 🔹 Actions
- `alert` → generate an alert/log  
- `drop` → drop the packet (inline mode)  
- `reject` → drop + send error back  
- `pass` → ignore traffic  

---

## 🔹 Source & Destination Options

### 1. **IP Addresses**
- Single IP → `192.168.1.10`  
- Subnet → `192.168.1.0/24`  
- Range → `[192.168.1.10,192.168.1.20]`  
- Negation → `!192.168.1.10`  
- Any → `any`  

### 2. **Ports**
- Single → `80`  
- Range → `1000:2000`, `:1024`, `1024:`  
- List → `[80,443,8080]`  
- Negation → `!22`  
- Any → `any`  

### 3. **Variables**
Defined in `suricata.yaml` or rule files:
- `$HOME_NET` → internal network(s)  
- `$EXTERNAL_NET` → usually `any` or `!$HOME_NET`  
- `$HTTP_PORTS`, `$SMTP_PORTS`, `$SSH_PORTS`  

Example:
```suricata
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"External to web"; sid:100005;)
```

### 4. **Combining Lists**
```suricata
alert tcp [192.168.1.10,10.0.0.5] [22,2222] -> $HOME_NET any (msg:"SSH from specific hosts"; sid:100006;)
```

---

## 🔹 Rule Options (inside parentheses)
- `content` → match exact string  
- `pcre` → regex matching  
- `flow` → track TCP direction/state (e.g., `to_server, established`)  
- `http.*` → inspect HTTP (e.g., `http.uri; content:"/admin";`)  
- `tls.*` → inspect TLS metadata (e.g., `tls.sni; content:"bad.com";`)  
- `threshold` → rate limiting alerts  
- `classtype` → classify type of alert  
- `priority` → severity (1=high, 3=low)  

---

## 🔹 Example Rules
**Detect HTTP URI access to `/admin`**
```suricata
alert http any any -> any any (msg:"Access to admin page"; http.uri; content:"/admin"; nocase; sid:100002; rev:1;)
```

**Detect suspicious TLS SNI (domain)**
```suricata
alert tls any any -> any any (msg:"Suspicious TLS domain"; tls.sni; content:"evil.com"; nocase; sid:100003; rev:1;)
```

**Block ICMP traffic**
```suricata
drop icmp any any -> any any (msg:"ICMP blocked"; sid:100004; rev:1;)
```

---

✅ With this guide, you can now **write, read, and customize Suricata rules** effectively.  
