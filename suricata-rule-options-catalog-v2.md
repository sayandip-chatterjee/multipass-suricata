# 📘 Suricata Rule Options Catalog

This document provides a **comprehensive list of Suricata rule options** (keywords inside `(...)`) with explanations, examples, and a quick reference cheat sheet.

---

## 🔹 1. Metadata & Identification
- **`msg:"text";`** → Human-readable alert message.  
- **`sid:12345;`** → Unique Signature ID.  
- **`rev:1;`** → Rule revision number.  
- **`gid:1;`** → Generator ID (1 = Suricata rules).  
- **`metadata:`** → Arbitrary metadata (e.g., `metadata: created_at 2025-08-29;`).  
- **`reference:`** → External reference (e.g., `reference:url,example.com;`).  
- **`tag:`** → Log additional packets after a match.  

---

## 🔹 2. Classification & Priority
- **`classtype:`** → Alert category (from `classification.config`).  
  Example: `classtype:protocol-command-decode;`  
- **`priority:`** → Alert severity (1=high, 3=low).  

---

## 🔹 3. Packet/Decode Events
Trigger on **decoder events** (malformed packets, protocol anomalies).  
Examples:  
- `decode-event:ipv4.pkt_too_small;`  
- `decode-event:tcp.pkt_too_small;`  
- `decode-event:udp.hlen_too_small;`  
- `decode-event:icmpv6.unknown_type;`  

---

## 🔹 4. Flow & Session Tracking
- **`flow:`** → Restrict by session state/direction.  
  Example: `flow:to_server,established;`  
- **`flowbits:`** → Set or check logical flags across rules.  
  - `flowbits:set,flag1;`  
  - `flowbits:isset,flag1;`  
  - `flowbits:unset,flag1;`  
- **`stream_size:`** → Match on stream size (e.g., `stream_size:>1000;`).  

---

## 🔹 5. Payload Content Matching
- **`content:"string";`** → Match literal string.  
- **`nocase;`** → Case-insensitive.  
- **`pcre:"/regex/";`** → Regex match.  
- **`offset:n; depth:m;`** → Restrict match to specific byte ranges.  
- **`distance:n; within:m;`** → Match relative to previous content.  
- **`fast_pattern;`** → Optimizes for fast scanning.  
- **`byte_test:`** → Compare numeric values.  
- **`byte_jump:`** → Skip bytes based on payload values.  
- **`isdataat:`** → Check if data exists at given offset.  

---

## 🔹 6. Protocol-Specific Keywords

### HTTP
- `http.method;` → HTTP method (GET, POST, etc.).  
- `http.uri;` → Request URI.  
- `http.host;` → Host header.  
- `http.header;` → Arbitrary header.  
- `http.cookie;` → Cookies.  
- `http.user_agent;` → User-Agent.  

### TLS
- `tls.sni;` → Server Name Indication (domain).  
- `tls.subject;` → Certificate subject.  
- `tls.issuerdn;` → Certificate issuer.  
- `tls.version;` → TLS version.  

### DNS
- `dns.query;` → Query name.  
- `dns.qtype;` → Query type.  
- `dns.id;` → Transaction ID.  

### SMB
- `smb.command;` → SMB command.  
- `smb.named_pipe;` → Named pipe name.  

### FTP
- `ftp.command;` → FTP command.  
- `ftp.reply;` → FTP server reply.  

(Also supports: SMTP, SSH, NFS, Modbus, DNP3, etc.)

---

## 🔹 7. Thresholding & Suppression
- **`threshold:`** → Rate-limit alerts.  
  ```suricata
  threshold:type limit, track by_src, count 1, seconds 60;
  ```
- **`detection_filter:`** → Simplified thresholding.  
- **`suppress:`** → Disable specific alerts.  

---

## 🔹 8. Logging & Output Control
- **`logto:"filename";`** → Log to a specific file.  
- **`sidmsg:"string";`** → Custom alert format.  

---

## 🔹 9. App-Layer Events
Match on application-layer events:  
- `app-layer-event:tls.invalid_cert;`  
- `app-layer-event:http.request_body_len_exceeded;`  
- `app-layer-event:smb.invalid_protocol;`  

---

## 🔹 10. File Handling
- **`file_data;`** → Inspect file data buffer.  
- **`filemagic:"PE32";`** → Match MIME/magic type.  
- **`filename:"malware.exe";`** → Match filename.  
- **`fileext:"exe";`** → Match file extension.  

---

## 🔹 Example Rule (Decode Event)
```suricata
alert ip any any -> any any (msg:"SURICATA IPv4 packet too small"; decode-event:ipv4.pkt_too_small; classtype:protocol-command-decode; sid:2200000; rev:2;)
```

**Explanation:**
- `msg` → Alert message  
- `decode-event:ipv4.pkt_too_small;` → Triggers on malformed IPv4 packet  
- `classtype:protocol-command-decode;` → Category  
- `sid:2200000;` → Signature ID  
- `rev:2;` → Revision  

---

## 📑 Quick Reference Cheat Sheet

| **Keyword**        | **Purpose**                                   | **Example** |
|---------------------|-----------------------------------------------|-------------|
| `msg`              | Alert message                                 | `msg:"Attack detected";` |
| `sid`              | Signature ID                                  | `sid:10001;` |
| `rev`              | Rule revision                                 | `rev:1;` |
| `classtype`        | Classify alert                                | `classtype:web-attack;` |
| `priority`         | Severity level                                | `priority:1;` |
| `decode-event`     | Trigger on decode anomaly                     | `decode-event:ipv4.pkt_too_small;` |
| `flow`             | Match flow state/direction                    | `flow:to_server,established;` |
| `flowbits`         | Track rule state across flows                 | `flowbits:set,shellcode;` |
| `content`          | Match fixed string                            | `content:"/admin";` |
| `pcre`             | Regex matching                                | `pcre:"/evil/i";` |
| `http.uri`         | Match HTTP URI                                | `http.uri; content:"/login";` |
| `tls.sni`          | Match TLS SNI                                 | `tls.sni; content:"bad.com";` |
| `dns.query`        | Match DNS query name                          | `dns.query; content:"malware.com";` |
| `threshold`        | Limit alerts per time window                  | `threshold:type limit, track by_src, count 1, seconds 60;` |
| `filemagic`        | Match file type                               | `filemagic:"PE32";` |
| `filename`         | Match filename                                | `filename:"malware.exe";` |

---

✅ Use this catalog as a **reference + cheatsheet** for writing and understanding Suricata rules.
