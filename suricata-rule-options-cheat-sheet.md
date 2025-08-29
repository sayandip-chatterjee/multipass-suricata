# 📑 Suricata Rule Options Cheat Sheet with Examples

This document provides a **comprehensive list of Suricata rule options** (keywords inside `(...)`) with explanations, examples, and a quick reference cheat sheet.

All Suricata rules follow the format:
```suricata
action protocol source_ip source_port -> dest_ip dest_port (option1; option2; ...;)
```
The options inside () define what exactly Suricata checks and how it handles a match.

---

## 🔹 Metadata & Identification
| Keyword      | Purpose | Example |
|--------------|---------|---------|
| `msg`        | Alert message | `msg:"Possible malware download";` |
| `sid`        | Signature ID | `sid:1000001;` |
| `rev`        | Rule revision | `rev:2;` |
| `gid`        | Generator ID | `gid:1;` |
| `metadata`   | Arbitrary metadata | `metadata: created_at 2025-08-29, policy security;` |
| `reference`  | External reference | `reference:cve,2024-1234; reference:url,example.com;` |
| `tag`        | Log extra packets | `tag:session,10,packets;` |
| `target`     | Alert target | `target:client;` |
| `service`    | Restrict by service | `service:http;` |

---

## 🔹 Classification & Priority
| Keyword      | Purpose | Example |
|--------------|---------|---------|
| `classtype`  | Classification type | `classtype:web-application-attack;` |
| `priority`   | Severity | `priority:1;` |

---

## 🔹 Flow & Session
| Keyword       | Purpose | Example |
|---------------|---------|---------|
| `flow`        | Flow state/direction | `flow:to_server,established;` |
| `flowbits`    | Track state | `flowbits:set,shellcode_detected;` / `flowbits:isset,shellcode_detected;` |
| `stream_size` | Match stream size | `stream_size:>1000;` |
| `flowint`     | Integer counter per flow | `flowint:score,+,1; flowint:score,>,5;` |
| `sameip`      | Match same src/dst IP | `sameip;` |

---

## 🔹 Packet / Decode Events
| Keyword        | Purpose | Example |
|----------------|---------|---------|
| `decode-event` | Trigger on malformed packets | `decode-event:ipv4.pkt_too_small;` |
| `engine-event` | Suricata internal events | `engine-event:stream.reassembly_error;` |

---

## 🔹 Payload Matching
| Keyword       | Purpose | Example |
|---------------|---------|---------|
| `content`     | Match string | `content:"/admin";` |
| `nocase`      | Case-insensitive | `content:"login"; nocase;` |
| `pcre`        | Regex | `pcre:"/cmd.exe/i";` |
| `offset`      | Start offset | `content:"USER"; offset:0;` |
| `depth`       | Limit match length | `content:"PASS"; depth:10;` |
| `distance`    | Distance from last match | `content:"="; distance:2;` |
| `within`      | Match window size | `content:"xyz"; within:5;` |
| `fast_pattern`| Fast pattern matcher | `content:"attack"; fast_pattern;` |
| `byte_test`   | Numeric test | `byte_test:2,>,1024,0;` |
| `byte_jump`   | Dynamic offset | `byte_jump:2,0,relative;` |
| `isdataat`    | Check data at offset | `isdataat:!4,relative;` |
| `base64_data` | Decode base64 | `base64_data; content:"MALICIOUS";` |

---

## 🔹 Buffer Modifiers (restrict `content`)
| Keyword          | Purpose | Example |
|------------------|---------|---------|
| `http.method`    | HTTP method | `http.method; content:"POST";` |
| `http.uri`       | HTTP URI | `http.uri; content:"/login";` |
| `http.host`      | HTTP Host | `http.host; content:"evil.com"; nocase;` |
| `http.header`    | HTTP header | `http.header; content:"Authorization";` |
| `http.cookie`    | Cookies | `http.cookie; content:"PHPSESSID";` |
| `http.user_agent`| User-Agent | `http.user_agent; content:"sqlmap"; nocase;` |
| `http.referer`   | Referer header | `http.referer; content:"phishing.com";` |
| `http.request_line` | Full HTTP request line | `http.request_line; content:"/admin";` |
| `http.response_line`| Full response line | `http.response_line; content:"200 OK";` |
| `http.stat_code` | HTTP status code | `http.stat_code; content:"404";` |
| `http.stat_msg`  | Status message | `http.stat_msg; content:"Not Found";` |
| `http.raw_uri`   | Raw URI | `http.raw_uri; content:"%2e%2e";` |
| `http.client_body` | HTTP request body | `http.client_body; content:"password=";` |
| `http.server_body` | HTTP response body | `http.server_body; content:"malware";` |
| `tls.sni`        | TLS SNI | `tls.sni; content:"bank.com"; nocase;` |
| `tls.subject`    | TLS subject | `tls.subject; content:"CN=BadCert";` |
| `tls.issuerdn`   | TLS issuer | `tls.issuerdn; content:"CN=FakeCA";` |
| `tls.version`    | TLS version | `tls.version; content:"TLS 1.0";` |
| `dns.query`      | DNS query | `dns.query; content:"malware.com";` |
| `dns.qtype`      | DNS type | `dns.qtype; content:"A";` |
| `dns.id`         | DNS ID | `dns.id; content:"1234";` |
| `smb.command`    | SMB command | `smb.command; content:"SMB_COM_WRITE";` |
| `smb.named_pipe` | SMB pipe | `smb.named_pipe; content:"\\spoolss";` |
| `ftp.command`    | FTP command | `ftp.command; content:"STOR";` |
| `ftp.reply`      | FTP reply | `ftp.reply; content:"230 Login successful";` |
| `ssh.protoversion` | SSH version | `ssh.protoversion; content:"2.0";` |
| `ssh.softwareversion` | SSH software | `ssh.softwareversion; content:"OpenSSH";` |
| `ike.spi`        | IKE SPI | `ike.spi; content:"0x12345678";` |
| `ike.doi`        | IKE DOI | `ike.doi; content:"IPSEC";` |
| `ike.exchtype`   | IKE exchange type | `ike.exchtype; content:"Identity Protection";` |
| `modbus.func_code` | Modbus function | `modbus.func_code; content:"05";` |
| `dnp3.func_code`   | DNP3 function | `dnp3.func_code; content:"READ";` |

---

## 🔹 Thresholding & Rate Control
| Keyword          | Purpose | Example |
|------------------|---------|---------|
| `threshold`      | Limit alerts | `threshold:type limit, track by_src, count 1, seconds 60;` |
| `detection_filter` | Simplified thresholding | `detection_filter:track by_src, count 10, seconds 60;` |
| `suppress`       | Suppress alerts | `suppress: track by_src, ip 192.168.1.10;` |

---

## 🔹 App-Layer & Engine Events
| Keyword           | Purpose | Example |
|-------------------|---------|---------|
| `app-layer-event` | Trigger on anomaly | `app-layer-event:http.request_body_len_exceeded;` |
| `engine-event`    | Engine-specific | `engine-event:decoder.event_failed;` |

---

## 🔹 File Handling
| Keyword     | Purpose | Example |
|-------------|---------|---------|
| `file_data` | Inspect file buffer | `file_data; content:"MZ";` |
| `filemagic` | Match file type | `filemagic:"PE32";` |
| `filename`  | Match filename | `filename:"malware.exe";` |
| `fileext`   | Match extension | `fileext:"exe";` |
| `filestore` | Store files | `filestore;` |
| `filemd5`   | Match MD5 hash | `filemd5:44d88612fea8a8f36de82e1278abb02f;` |
| `filesha1`  | Match SHA1 hash | `filesha1:da39a3ee5e6b4b0d3255bfef95601890afd80709;` |
| `filesha256`| Match SHA256 hash | `filesha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;` |

---

## 🔹 Miscellaneous
| Keyword   | Purpose | Example |
|-----------|---------|---------|
| `activated_by` | Activates rule | `activated_by:1000001;` |
| `activates`    | Linked rule | `activates:2000001;` |
| `replace`      | Replace content | `replace:"HACKED";` |
| `byte_extract` | Extract value | `byte_extract:4,0,id,relative;` |
| `pkt_data`     | Match raw packet | `pkt_data; content:"\x90\x90\x90";` |
| `ipopts`       | Match IP options | `ipopts:lsrr;` |
| `fragbits`     | Match fragment bits | `fragbits:M;` |
| `fragoffset`   | Match fragment offset | `fragoffset:0;` |
| `ttl`          | Match TTL | `ttl:128;` |
| `tos`          | Match TOS | `tos:16;` |
| `id`           | Match IP ID | `id:12345;` |
| `ip_proto`     | Match IP protocol | `ip_proto:6;` |
| `flags`        | Match TCP flags | `flags:S;` |
| `seq`          | Match TCP seq number | `seq:12345;` |
| `ack`          | Match TCP ack number | `ack:67890;` |
| `window`       | Match TCP window size | `window:1024;` |

---

✅ This is now a **complete quick reference with examples** for nearly every Suricata keyword inside `( )`.  
