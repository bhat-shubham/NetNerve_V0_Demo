# ============================================================
# NetNerve Demo Backend — main.py
# Upgraded with full deterministic threat detection engine
# Architecture: detect with code → narrate with AI
# ============================================================

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, UploadFile, Body
from pydantic import BaseModel
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from collections import Counter, defaultdict
from urllib.parse import unquote
from math import log2
from typing import Optional

import uuid, os, re, statistics, ipaddress
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles

load_dotenv()
from groq import Groq

app = FastAPI()
if os.path.isdir("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
system_prompt = os.environ.get("SYSTEM_PROMPT") or (
    "You are a senior network security analyst. "
    "You write precise, evidence-based reports. "
    "You never speculate beyond what the data shows."
)

# ============================================================
# Pydantic Models
# ============================================================

class SummaryRequest(BaseModel):
    protocols: list[str]
    packet_data: list[dict]
    total_data_size: int
    classification: Optional[dict] = None

# ============================================================
# Helpers
# ============================================================

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c / total) * log2(c / total) for c in freq.values() if c > 0)


def _escalate(state: dict, verdict: str, severity: str) -> None:
    rank_v = {"Clean": 0, "Anomaly Detected": 1, "Potential Threat": 2, "Confirmed Attack": 3}
    rank_s = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    if rank_v.get(verdict, 0) > rank_v.get(state["verdict"], 0):
        state["verdict"] = verdict
    if rank_s.get(severity, 0) > rank_s.get(state["severity"], 0):
        state["severity"] = severity


def _finding(ftype: str, severity: str, confirmed: bool, evidence: str) -> dict:
    return {"type": ftype, "severity": severity, "confirmed": confirmed, "evidence": evidence}

# ============================================================
# Payload Threat Scanner
# ============================================================

def scan_payload_for_threats(payload: str) -> list:
    if not payload:
        return []
    threats = []
    pl = payload.lower()
    # SQLi
    for pat in [
        "union select", "union all select", "drop table", "or 1=1",
        "or '1'='1", "sleep(", "waitfor delay", "benchmark(",
        "information_schema", "select * from", "select @@version",
        "into outfile", "load_file(", "exec xp_", "exec sp_",
        "' or 1", "\" or 1",
    ]:
        if pat in pl:
            threats.append(f"SQLi: {pat}")
    # XSS
    if "<script>" in pl or "javascript:" in pl or "onerror=" in pl:
        threats.append("XSS: Script Execution")
    # Command injection
    for pat in ["; cat ", "| nc ", "&& whoami", "; ls", "| wget", "; ping", "| curl"]:
        if pat in pl:
            threats.append(f"Cmd Inj: {pat}")
    # Path traversal / LFI
    for pat in ["../", "..\\", "/etc/passwd", "win.ini", "%2e%2e%2f"]:
        if pat in pl:
            threats.append(f"Path Trav: {pat}")
    # RCE
    for pat in ["eval(", "system(", "phpinfo()", "exec(", "passthru(", "shell_exec("]:
        if pat in pl:
            threats.append(f"RCE: {pat}")
    return threats

# ============================================================
# Packet Extractor (Scapy)
# ============================================================

def extract_packet_data(file_path: str) -> list:
    packets = rdpcap(file_path)
    data = []

    for pkt in packets:
        pkt_info = {}

        if IP in pkt:
            pkt_info["src_ip"]     = pkt[IP].src
            pkt_info["dst_ip"]     = pkt[IP].dst
            pkt_info["packet_len"] = len(pkt)
            pkt_info["timestamp"]  = float(pkt.time)

            if TCP in pkt:
                pkt_info["protocol"] = "TCP"
                pkt_info["src_port"] = pkt[TCP].sport
                pkt_info["dst_port"] = pkt[TCP].dport
                pkt_info["flags"]    = str(pkt[TCP].flags)
                if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                    pkt_info["protocol"] = "FTP"
                if pkt[TCP].dport == 23 or pkt[TCP].sport == 23:
                    pkt_info["protocol"] = "Telnet"

            elif UDP in pkt:
                pkt_info["protocol"] = "UDP"
                pkt_info["src_port"] = pkt[UDP].sport
                pkt_info["dst_port"] = pkt[UDP].dport

            elif ICMP in pkt:
                pkt_info["protocol"] = "ICMP"

        elif ARP in pkt:
            pkt_info["protocol"] = "ARP"

        # DNS
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt[DNS]:
            try:
                pkt_info["dns_query"] = pkt[DNS][DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                pkt_info["protocol"]  = "DNS"
            except Exception:
                pass

        # HTTP + payload scanning
        if Raw in pkt:
            try:
                raw = pkt[Raw].load[:4096].decode("utf-8", errors="ignore")
                if raw.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    pkt_info["protocol"]    = "HTTP"
                    pkt_info["http_method"] = raw.split(" ")[0]
                    hm = re.search(r"Host:\s*([^\r\n]+)", raw, re.IGNORECASE)
                    if hm: pkt_info["http_host"] = hm.group(1).strip()
                    ua = re.search(r"User-Agent:\s*([^\r\n]+)", raw, re.IGNORECASE)
                    if ua: pkt_info["http_ua"] = ua.group(1).strip()
                    auth = re.search(r"Authorization:\s*Basic\s+", raw, re.IGNORECASE)
                    if auth: pkt_info["creds_seen"] = True
                pkt_info["payload"] = unquote(raw)[:500]
            except Exception:
                pass

        if pkt_info:
            data.append(pkt_info)

    return data

# ============================================================
# Statistics
# ============================================================

def calculate_statistics(packet_data: list) -> dict:
    if not packet_data:
        return {}

    stats = {
        "protocols": Counter(), "src_ips": Counter(),
        "dst_ips": Counter(), "dst_ports": Counter(),
        "flags": Counter(), "total_packets": len(packet_data),
        "suspicious_flags": 0, "total_len": 0,
        "threats": Counter(),
    }
    syn = rst = udp = icmp = 0
    min_time = float("inf")
    max_time = float("-inf")

    for pkt in packet_data:
        p = pkt.get("protocol", "Unknown")
        stats["protocols"][p] += 1
        stats["total_len"]    += pkt.get("packet_len", 0)
        ts = pkt.get("timestamp", 0)
        if ts > 946684800:
            if ts < min_time: min_time = ts
            if ts > max_time: max_time = ts
        if "payload" in pkt:
            for t in scan_payload_for_threats(pkt["payload"]):
                stats["threats"][t] += 1
        if p == "UDP":  udp  += 1
        if p == "ICMP": icmp += 1
        if "src_ip"   in pkt: stats["src_ips"][pkt["src_ip"]]    += 1
        if "dst_ip"   in pkt: stats["dst_ips"][pkt["dst_ip"]]    += 1
        if "dst_port" in pkt: stats["dst_ports"][pkt["dst_port"]] += 1
        if "flags" in pkt:
            f = pkt["flags"]
            stats["flags"][f] += 1
            if "S" in f: syn += 1
            if "R" in f:
                rst += 1
                stats["suspicious_flags"] += 1

    stats["duration"] = max_time - min_time if min_time != float("inf") else 0
    if stats["duration"] > 31536000:
        stats["duration"] = 0
    n   = stats["total_packets"]
    dur = max(stats["duration"], 1.0)
    stats.update({
        "pps":            n / dur,
        "bps":            stats["total_len"] / dur,
        "unique_src_ips": len(stats["src_ips"]),
        "unique_dst_ips": len(stats["dst_ips"]),
        "avg_len":        stats["total_len"] / n if n > 0 else 0,
        "syn_ratio":      syn  / n if n > 0 else 0,
        "rst_ratio":      rst  / n if n > 0 else 0,
        "udp_ratio":      udp  / n if n > 0 else 0,
        "icmp_ratio":     icmp / n if n > 0 else 0,
    })
    return stats

# ============================================================
# Threat Classifier (ported from prod, trimmed to essentials)
# ============================================================

def classify_threats(stats: dict, packet_data: list) -> dict:
    findings     = []
    attack_types = []
    state        = {"verdict": "Clean", "severity": "Info"}

    total = stats.get("total_packets", 0)
    if total == 0:
        return {"verdict": "Clean", "severity": "Info", "findings": [], "attack_types": []}

    syn_ratio  = stats.get("syn_ratio", 0)
    rst_ratio  = stats.get("rst_ratio", 0)
    udp_ratio  = stats.get("udp_ratio", 0)
    icmp_ratio = stats.get("icmp_ratio", 0)
    pps        = stats.get("pps", 0)
    threats    = stats.get("threats", Counter())
    protocols  = stats.get("protocols", Counter())
    dst_ports  = stats.get("dst_ports", Counter())
    src_ips    = stats.get("src_ips", Counter())
    dst_ips    = stats.get("dst_ips", Counter())
    duration   = stats.get("duration", 0)

    top_src_ip, top_src_count = src_ips.most_common(1)[0] if src_ips else (None, 0)
    top_dst_ip, top_dst_count = dst_ips.most_common(1)[0] if dst_ips else (None, 0)
    src_concentration = top_src_count / total if total > 0 else 0
    unique_dst_ports  = len(dst_ports)

    top_src_set = set(ip for ip, _ in src_ips.most_common(10))
    top_dst_set = set(ip for ip, _ in dst_ips.most_common(10))
    is_bidirectional = len(top_src_set & top_dst_set) > 0

    dns_queries = [p.get("dns_query", "") for p in packet_data if p.get("dns_query")]
    http_uas    = [p.get("http_ua",    "") for p in packet_data if p.get("http_ua")]
    payloads    = [p.get("payload",    "") for p in packet_data if p.get("payload")]

    # Flow tracking
    flows = defaultdict(lambda: {"bytes": 0, "packets": 0, "timestamps": []})
    for p in packet_data:
        src, dst = p.get("src_ip"), p.get("dst_ip")
        if src and dst:
            key = (src, dst)
            flows[key]["bytes"]   += p.get("packet_len", 0)
            flows[key]["packets"] += 1
            if p.get("timestamp", 0) > 946684800:
                flows[key]["timestamps"].append(p["timestamp"])

    # ── 1. Payload injection ────────────────────────────────
    if threats:
        sqli = [(t, c) for t, c in threats.items() if "SQLi" in t]
        xss  = [(t, c) for t, c in threats.items() if "XSS"  in t]
        rce  = [(t, c) for t, c in threats.items() if "RCE"  in t]
        cmd  = [(t, c) for t, c in threats.items() if "Cmd"  in t]
        lfi  = [(t, c) for t, c in threats.items() if "Path" in t]

        if sqli:
            findings.append(_finding("SQL_INJECTION", "Critical", True,
                f"{sum(c for _,c in sqli)} SQL injection payloads confirmed. "
                f"Techniques: {', '.join(t.replace('SQLi: ','') for t,_ in sqli[:3])}. "
                f"Source: {top_src_ip}."))
            attack_types.append("SQL_INJECTION")
            _escalate(state, "Confirmed Attack", "Critical")

        if xss:
            findings.append(_finding("CROSS_SITE_SCRIPTING", "High", True,
                f"{sum(c for _,c in xss)} XSS payloads in HTTP traffic. Source: {top_src_ip}."))
            attack_types.append("XSS")
            _escalate(state, "Confirmed Attack", "High")

        if rce:
            findings.append(_finding("REMOTE_CODE_EXECUTION", "Critical", True,
                f"RCE patterns confirmed: {', '.join(t.replace('RCE: ','') for t,_ in rce[:3])}. "
                f"Source: {top_src_ip}."))
            attack_types.append("RCE")
            _escalate(state, "Confirmed Attack", "Critical")

        if cmd:
            findings.append(_finding("COMMAND_INJECTION", "High", True,
                f"OS command injection: {', '.join(t.replace('Cmd Inj: ','') for t,_ in cmd[:3])}. "
                f"Source: {top_src_ip}."))
            attack_types.append("COMMAND_INJECTION")
            _escalate(state, "Confirmed Attack", "High")

        if lfi:
            findings.append(_finding("PATH_TRAVERSAL_LFI", "High", True,
                f"Path traversal patterns: {', '.join(t.replace('Path Trav: ','') for t,_ in lfi[:3])}. "
                f"Source: {top_src_ip}."))
            attack_types.append("PATH_TRAVERSAL")
            _escalate(state, "Confirmed Attack", "High")

    # ── 2. Volumetric / Flood ───────────────────────────────
    if not is_bidirectional:
        if syn_ratio > 0.80 and pps > 1000:
            findings.append(_finding("SYN_FLOOD", "Critical", True,
                f"SYN ratio {syn_ratio:.1%} at {pps:,.0f} PPS unidirectional. "
                f"Source: {top_src_ip}. Target: {top_dst_ip}."))
            attack_types.append("SYN_FLOOD")
            _escalate(state, "Confirmed Attack", "Critical")

        elif syn_ratio > 0.50 and pps > 200:
            findings.append(_finding("SYN_SCAN", "High", True,
                f"SYN ratio {syn_ratio:.1%} at {pps:.0f} PPS unidirectional. "
                f"Half-open connection pattern from {top_src_ip}."))
            attack_types.append("SYN_SCAN")
            _escalate(state, "Confirmed Attack", "High")

        if udp_ratio > 0.70 and pps > 5000:
            findings.append(_finding("UDP_FLOOD", "Critical", True,
                f"UDP ratio {udp_ratio:.1%} at {pps:,.0f} PPS unidirectional. "
                f"{protocols.get('UDP',0):,} UDP packets from {top_src_ip} to {top_dst_ip}."))
            attack_types.append("UDP_FLOOD")
            _escalate(state, "Confirmed Attack", "Critical")

        if icmp_ratio > 0.50 and pps > 1000:
            findings.append(_finding("ICMP_FLOOD", "High", True,
                f"ICMP ratio {icmp_ratio:.1%} at {pps:.0f} PPS unidirectional. "
                f"ICMP flood against {top_dst_ip}."))
            attack_types.append("ICMP_FLOOD")
            _escalate(state, "Confirmed Attack", "High")

        if pps > 50000:
            findings.append(_finding("VOLUMETRIC_DDOS", "Critical", True,
                f"{pps:,.0f} PPS unidirectional — exceeds DDoS threshold of 50k PPS. "
                f"Target: {top_dst_ip}."))
            attack_types.append("VOLUMETRIC_DDOS")
            _escalate(state, "Confirmed Attack", "Critical")

    # ── 3. Port Scan ────────────────────────────────────────
    if unique_dst_ports > 100 and src_concentration > 0.60:
        findings.append(_finding("PORT_SCAN", "High", True,
            f"{unique_dst_ports} unique destination ports targeted. "
            f"{top_src_ip} accounts for {src_concentration:.0%} of traffic. "
            f"Consistent with nmap/masscan port scan."))
        attack_types.append("PORT_SCAN")
        _escalate(state, "Confirmed Attack", "High")

    elif unique_dst_ports > 30 and src_concentration > 0.50:
        findings.append(_finding("PORT_SCAN_SUSPECTED", "Medium", False,
            f"{unique_dst_ports} unique ports from {top_src_ip} ({src_concentration:.0%} of traffic). "
            f"Possible reconnaissance."))
        _escalate(state, "Potential Threat", "Medium")

    # ── 4. DNS Exfiltration ─────────────────────────────────
    if dns_queries:
        long_queries = [q for q in dns_queries if len(q) > 52]
        high_entropy = [q for q in dns_queries if _entropy(q.split(".")[0]) > 3.5]

        if len(long_queries) > 20:
            findings.append(_finding("DNS_EXFILTRATION_SUSPECTED", "High", False,
                f"{len(long_queries)} DNS queries with subdomain > 52 chars. "
                f"Sample: '{long_queries[0][:50]}...'. "
                f"Long subdomains indicate DNS tunneling (dnscat2/iodine)."))
            attack_types.append("DNS_EXFILTRATION")
            _escalate(state, "Potential Threat", "High")

        if len(high_entropy) > 15:
            findings.append(_finding("DNS_HIGH_ENTROPY", "High", False,
                f"{len(high_entropy)} DNS queries with Shannon entropy > 3.5. "
                f"Indicates base64/hex-encoded payloads — possible DGA malware or tunneling."))
            _escalate(state, "Potential Threat", "High")

        if duration > 0 and len(dns_queries) / max(duration, 1) > 100:
            findings.append(_finding("DNS_FLOOD", "High", True,
                f"{len(dns_queries)/max(duration,1):.0f} DNS queries/sec — exceeds 100 QPS threshold."))
            attack_types.append("DNS_FLOOD")
            _escalate(state, "Confirmed Attack", "High")

    # ── 5. ICMP Tunneling ───────────────────────────────────
    icmp_pkts = [p for p in packet_data if p.get("protocol") == "ICMP"]
    large_icmp = [p for p in icmp_pkts if p.get("packet_len", 0) > 200]
    if len(large_icmp) > 20:
        avg_size = sum(p.get("packet_len", 0) for p in large_icmp) / len(large_icmp)
        findings.append(_finding("ICMP_TUNNELING_SUSPECTED", "High", False,
            f"{len(large_icmp)} ICMP packets > 200 bytes (avg {avg_size:.0f}B). "
            f"Normal ping is 64-84B. Indicates ICMP tunneling (ptunnel/icmptunnel)."))
        attack_types.append("ICMP_TUNNELING")
        _escalate(state, "Potential Threat", "High")

    # ── 6. C2 Beaconing ─────────────────────────────────────
    for (src, dst), fdata in flows.items():
        ts_list = sorted(fdata["timestamps"])
        if len(ts_list) < 8:
            continue
        try:
            dst_obj = ipaddress.ip_address(dst)
            if dst_obj.is_private:
                continue
        except Exception:
            continue
        intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list)-1)]
        if not intervals or min(intervals) < 0.001:
            continue
        try:
            mean_i = statistics.mean(intervals)
            stdev_i = statistics.stdev(intervals) if len(intervals) > 1 else 0
            cv = stdev_i / mean_i if mean_i > 0 else 1
        except Exception:
            continue
        if cv < 0.25 and 10 <= mean_i <= 3600 and len(ts_list) >= 10:
            findings.append(_finding("C2_BEACONING_SUSPECTED", "High", False,
                f"Flow {src} → {dst}: {len(ts_list)} connections, "
                f"interval {mean_i:.1f}s ± {stdev_i:.1f}s (CV={cv:.2f}). "
                f"Automated timer-driven connections — consistent with C2 beaconing."))
            if "C2_BEACONING" not in attack_types:
                attack_types.append("C2_BEACONING")
            _escalate(state, "Potential Threat", "High")
            break  # one finding is enough for demo

    # ── 7. ARP Flood / Scan ─────────────────────────────────
    arp_pkts = [p for p in packet_data if p.get("protocol") == "ARP"]
    if arp_pkts:
        arp_rate = len(arp_pkts) / max(duration, 1)
        if arp_rate > 50 and len(arp_pkts) > 200:
            findings.append(_finding("ARP_FLOOD", "High", True,
                f"{len(arp_pkts)} ARP packets at {arp_rate:.0f}/sec. "
                f"CAM table overflow — forces broadcast mode enabling sniffing."))
            attack_types.append("ARP_FLOOD")
            _escalate(state, "Confirmed Attack", "High")
        elif len(arp_pkts) > 100 and not is_bidirectional:
            findings.append(_finding("ARP_SCAN", "Medium", False,
                f"{len(arp_pkts)} ARP requests unidirectional — possible host discovery sweep."))
            _escalate(state, "Potential Threat", "Medium")

    # ── 8. Lateral Movement ─────────────────────────────────
    smb = dst_ports.get(445, 0) + dst_ports.get(139, 0)
    if smb > 100 and src_concentration > 0.60:
        findings.append(_finding("SMB_LATERAL_MOVEMENT", "High", False,
            f"{smb} packets to SMB (445/139) from {top_src_ip}. "
            f"Consistent with lateral movement, pass-the-hash, or ransomware propagation."))
        attack_types.append("SMB_LATERAL_MOVEMENT")
        _escalate(state, "Potential Threat", "High")

    rdp = dst_ports.get(3389, 0)
    if rdp > 100 and src_concentration > 0.50:
        findings.append(_finding("RDP_BRUTE_FORCE", "High", False,
            f"{rdp} packets to RDP (3389) from {top_src_ip}. "
            f"High-frequency RDP targeting — credential brute force suspected."))
        attack_types.append("RDP_BRUTE_FORCE")
        _escalate(state, "Potential Threat", "High")

    ssh = dst_ports.get(22, 0)
    if ssh > 200 and src_concentration > 0.50:
        findings.append(_finding("SSH_BRUTE_FORCE", "High", False,
            f"{ssh} packets to SSH (22) from {top_src_ip}. "
            f"High-frequency SSH targeting — hydra/medusa brute force suspected."))
        attack_types.append("SSH_BRUTE_FORCE")
        _escalate(state, "Potential Threat", "High")

    # ── 9. Cleartext Credentials ────────────────────────────
    cred_pkts = [p for p in packet_data if p.get("creds_seen")]
    if cred_pkts:
        findings.append(_finding("CREDENTIAL_EXPOSURE", "High", True,
            f"{len(cred_pkts)} HTTP Basic Auth headers captured in cleartext. "
            f"Base64-encoded credentials — trivially decoded."))
        attack_types.append("CREDENTIAL_EXPOSURE")
        _escalate(state, "Confirmed Attack", "High")

    telnet_pkts = [p for p in packet_data if p.get("protocol") == "Telnet"]
    if len(telnet_pkts) > 10:
        findings.append(_finding("CLEARTEXT_TELNET", "High", True,
            f"{len(telnet_pkts)} Telnet packets detected. "
            f"All data including credentials transmitted in plaintext."))
        _escalate(state, "Potential Threat", "High")

    # ── 10. Attack Tool User-Agents ─────────────────────────
    ua_blacklist = ["sqlmap", "nikto", "nmap", "dirbuster", "gobuster",
                    "burpsuite", "hydra", "metasploit", "nuclei", "masscan"]
    detected_tools = []
    for ua in set(http_uas):
        for tool in ua_blacklist:
            if tool in ua.lower():
                detected_tools.append(tool)
                break
    if detected_tools:
        findings.append(_finding("ATTACK_TOOL_DETECTED", "High", True,
            f"Attack tool User-Agents detected: {', '.join(set(detected_tools))}. "
            f"Source: {top_src_ip}."))
        attack_types.append("ATTACK_TOOL")
        _escalate(state, "Confirmed Attack", "High")

    # ── 11. Web Directory Scan ──────────────────────────────
    scan_paths = ["/admin", "/wp-admin", "/.env", "/.git", "/phpinfo", "/backup", "/config"]
    payload_blob = " ".join(payloads[:300]).lower()
    matched_paths = [p for p in scan_paths if p in payload_blob]
    if len(matched_paths) >= 3:
        findings.append(_finding("WEB_DIRECTORY_SCAN", "Medium", True,
            f"Web path scanning: {', '.join(matched_paths[:5])} probed. "
            f"Automated web reconnaissance from {top_src_ip}."))
        attack_types.append("WEB_SCAN")
        _escalate(state, "Confirmed Attack", "Medium")

    # ── 12. RST Injection ───────────────────────────────────
    if rst_ratio > 0.40 and total > 500:
        findings.append(_finding("HIGH_RST_RATE", "Medium", False,
            f"RST ratio {rst_ratio:.1%} ({int(rst_ratio*total):,} RST packets). "
            f"Possible RST injection, port scan response traffic, or aggressive IPS."))
        _escalate(state, "Anomaly Detected", "Medium")

    # ── 13. Traffic Concentration Anomaly ───────────────────
    if (src_concentration > 0.90 and total > 1000
            and "PORT_SCAN" not in attack_types
            and "SYN_FLOOD" not in attack_types):
        findings.append(_finding("TRAFFIC_CONCENTRATION", "Low", False,
            f"Single source {top_src_ip} = {src_concentration:.0%} of all {total:,} packets. "
            f"Possible misconfiguration or early-stage reconnaissance."))
        _escalate(state, "Anomaly Detected", "Low")

    # ── Clean ────────────────────────────────────────────────
    if not findings:
        top_proto = protocols.most_common(1)[0] if protocols else ("Unknown", 0)
        findings.append(_finding("NO_THREATS_DETECTED", "Info", True,
            f"No attack signatures or anomalous patterns detected across {total:,} packets. "
            f"Dominant protocol: {top_proto[0]} ({top_proto[1]:,} pkts). "
            f"Traffic appears consistent with normal operations."))

    return {
        "verdict":      state["verdict"],
        "severity":     state["severity"],
        "findings":     findings,
        "attack_types": attack_types,
    }

# ============================================================
# Upload Endpoint
# ============================================================

@app.get("/")
async def root():
    return {"message": "NetNerve demo backend is live!"}


@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile):
    MAX_FILE_SIZE_MB = 10
    valid_extensions = [".pcap", ".cap"]

    if not (file.filename and file.filename.lower().endswith(tuple(valid_extensions))):
        raise HTTPException(status_code=400, detail="Invalid file extension.")

    file_head = await file.read(2048)
    content   = file_head + await file.read()

    if len(content) > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds the limit of 10MB.")

    file_path = f"{uuid.uuid4()}.pcap"
    with open(file_path, "wb") as f:
        f.write(content)

    try:
        packet_data = extract_packet_data(file_path)
        stats       = calculate_statistics(packet_data)
        classif     = classify_threats(stats, packet_data)

        # Derive protocol set from stats — avoids a second rdpcap() pass
        protocols_set = set(stats["protocols"].keys())

        total_data_size = sum(p.get("packet_len", 0) for p in packet_data)

        return {
            "protocols":      list(protocols_set),
            "packet_data":    packet_data,
            "total_data_size": total_data_size,
            "stats":          {
                "total_packets":  stats.get("total_packets", 0),
                "pps":            round(stats.get("pps", 0), 2),
                "syn_ratio":      round(stats.get("syn_ratio", 0), 4),
                "udp_ratio":      round(stats.get("udp_ratio", 0), 4),
                "icmp_ratio":     round(stats.get("icmp_ratio", 0), 4),
                "duration":       round(stats.get("duration", 0), 2),
                "unique_src_ips": stats.get("unique_src_ips", 0),
                "unique_dst_ips": stats.get("unique_dst_ips", 0),
            },
            "classification": classif,
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid or corrupted pcap file: {e}")
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

# ============================================================
# Summary Endpoint
# ============================================================

def build_summary_prompt(
        protocols: list,
        packet_data: list,
        total_data_size: int,
        classification: dict | None = None,
) -> str:
    lines = []
    lines.append(f"Protocols used: {', '.join(protocols)}.")
    lines.append(f"Total packets captured: {len(packet_data)}.")
    lines.append(f"Total data transferred: {total_data_size} bytes.")

    if packet_data:
        for i, pkt in enumerate(packet_data[:5], 1):
            lines.append(
                f"Sample {i}: {pkt.get('src_ip')}:{pkt.get('src_port')} → "
                f"{pkt.get('dst_ip')}:{pkt.get('dst_port')} | {pkt.get('protocol')} "
                f"| Size: {pkt.get('packet_len')} bytes | Flags: {pkt.get('flags')}."
            )

    # Inject deterministic classification into prompt so AI only narrates
    if classification:
        verdict  = classification.get("verdict", "Unknown")
        severity = classification.get("severity", "Unknown")
        findings = classification.get("findings", [])
        types    = classification.get("attack_types", [])

        lines.append(f"\n=== DETERMINISTIC CLASSIFICATION (GROUND TRUTH) ===")
        lines.append(f"Verdict: {verdict} | Severity: {severity}")
        lines.append(f"Attack types confirmed: {', '.join(types) or 'None'}")
        lines.append("Findings (do not override, only narrate):")
        for f in findings:
            tag = "✓ CONFIRMED" if f["confirmed"] else "? SUSPECTED"
            lines.append(f"  [{f['severity']}] {tag} {f['type']}: {f['evidence']}")

        lines.append(
            "\n=== FORMATTING RULES (MANDATORY - MUST FOLLOW EXACTLY) ===\n"
            "1. Start with ## VERDICT: [severity level]\n"
            "2. Then ## SEVERITY: [severity word]\n"
            "3. Then ## FINDINGS:\n"
            "4. Then list EACH finding as a separate bullet point starting with '- '\n"
            "5. Then ## RECOMMENDATIONS:\n"
            "6. Then list EACH recommendation as a separate bullet point starting with '- '\n"
            "\n"
            "CRITICAL: Each bullet point MUST be on its own line. Do NOT merge findings on one line.\n"
            "CRITICAL: Each recommendation MUST be on its own line. Do NOT merge recommendations.\n"
            "CRITICAL: Use only markdown formatting. Do NOT use bold text or other formatting.\n"
            "\n=== EXACT OUTPUT FORMAT (follow this template exactly) ===\n\n"
            "## VERDICT: Confirmed Attack\n"
            "## SEVERITY: [severity_level_here]\n"
            "## FINDINGS:\n"
            "- [First finding with evidence and attack type]\n"
            "- [Second finding with evidence and attack type]\n"
            "- [Third finding if applicable]\n"
            "## RECOMMENDATIONS:\n"
            "- [First specific recommendation]\n"
            "- [Second specific recommendation]\n"
            "- [Third specific recommendation if applicable]\n\n"
            "=== NOW GENERATE THE REPORT ===\n"
            "Report must be under 400 words. Use ONLY the findings provided above. Do NOT invent."
        )
    else:
        lines.append(
            "Analyze this capture for potential threats, patterns, or observations "
            "and add a severity score at the top of the report."
        )

    return "\n".join(lines)


async def generate_ai_summary(
        protocols: list,
        packet_data: list,
        total_data_size: int,
        classification: dict | None = None,
) -> str:
    user_prompt = build_summary_prompt(protocols, packet_data, total_data_size, classification)
    chat = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
    )
    return chat.choices[0].message.content


@app.post("/generate-summary/")
async def generate_summary(request: SummaryRequest):
    try:
        summary = await generate_ai_summary(
            request.protocols, 
            request.packet_data, 
            request.total_data_size, 
            request.classification
        )
        return {"summary": [summary]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Summary failed: {e}")