# NetNerve — V0 Demo

**This is the archived V0 prototype. It is not the production codebase.**

The service at [netnerve.online](https://netnerve.online) runs a different, private repository with a different detection stack (see [What changed since V0](#what-changed-since-v0)). This repo is published so the original approach can be read and run — not because it is what serves users today.

[![Status](https://img.shields.io/badge/status-archived%20demo-orange)](https://github.com/bhat-shubham/NetNerve_V0_Demo)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![Production](https://img.shields.io/badge/production-netnerve.online-brightgreen)](https://netnerve.online)

## What it does

Upload a `.pcap` or `.cap` file. The FastAPI backend parses every packet with Scapy, runs a deterministic rule engine over the result, and returns a verdict plus findings. The frontend then sends those findings to a commercial LLM API, which writes a short analyst-style report.

The design rule is **detect with code, narrate with AI**. The model receives the confirmed findings as ground truth and is instructed not to override them.

## Architecture

```
browser — Next.js 15 (app/, components/ui/)
  │
  │  POST /uploadfile/        multipart .pcap / .cap
  ▼
FastAPI — backend/main.py
  │  Scapy rdpcap()  →  per-packet records
  │  rule engine     →  verdict, severity, findings, attack_types
  │  temp file deleted in finally{}
  │
  │  POST /generate-summary/  (frontend sends records + findings)
  ▼
Commercial LLM API  →  markdown report
```

## Detection engine

All thresholds below are the ones in `classify_threats()` in `backend/main.py`.

| Category | Signal |
|---|---|
| SQL injection | Payload contains `union select`, `or 1=1`, `sleep(`, `into outfile`, `information_schema`, … |
| XSS | `<script>`, `javascript:`, `onerror=` |
| Command injection | `; cat `, `\| nc `, `&& whoami`, `\| wget`, `\| curl` |
| Path traversal / LFI | `../`, `..\`, `/etc/passwd`, `win.ini`, `%2e%2e%2f` |
| RCE | `eval(`, `system(`, `passthru(`, `shell_exec(`, `phpinfo()` |
| SYN flood | SYN ratio > 80% at > 1,000 PPS, unidirectional |
| SYN scan | SYN ratio > 50% at > 200 PPS, unidirectional |
| UDP / ICMP flood | UDP > 70% at > 5,000 PPS; ICMP > 50% at > 1,000 PPS |
| Volumetric DDoS | > 50,000 PPS unidirectional |
| Port scan | > 100 destination ports from one source holding > 60% of traffic |
| DNS exfiltration | > 20 queries with a subdomain longer than 52 characters |
| DNS entropy | > 15 queries with Shannon entropy > 3.5 on the first label |
| DNS flood | > 100 queries/sec |
| ICMP tunneling | > 20 ICMP packets larger than 200 bytes |
| C2 beaconing | ≥ 10 connections to a public IP, interval 10s–1h, coefficient of variation < 0.25 |
| ARP flood / scan | > 50 ARP/sec and > 200 packets, or > 100 unidirectional ARP requests |
| Lateral movement | > 100 packets to SMB 445/139, or RDP 3389, or SSH 22, from one dominant source |
| Cleartext credentials | HTTP Basic Auth headers, or > 10 Telnet packets |
| Attack tooling | `sqlmap`, `nikto`, `nmap`, `gobuster`, `burpsuite`, `hydra`, `metasploit`, `nuclei`, `masscan` in User-Agent |
| Web directory scan | ≥ 3 of `/admin`, `/wp-admin`, `/.env`, `/.git`, `/phpinfo`, `/backup`, `/config` |
| RST injection | RST ratio > 40% across > 500 packets |
| Traffic concentration | One source > 90% of packets |

Findings are marked **confirmed** or **suspected**. The report keeps that distinction.

## Limits and known gaps

- `.pcap` and `.cap` only. No `.pcapng`.
- 10 MB maximum, enforced by the backend (`MAX_FILE_SIZE_MB = 10`) and the dropzone. The upload copy still says "below 2 MB" — that text is stale.
- The whole capture is loaded into memory by `rdpcap()`. Large files will be slow or fail.
- No authentication, no rate limiting, `allow_origins=["*"]`. Treat this as a local demo, not a public service.
- Up to 500 characters of decoded payload per packet are included in the request to the model. The production build strips payload and raw bytes before any model call.

## Run locally

Requirements: Node 18+, Python 3.10+.

**Backend**

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create `backend/.env`:

```bash
GROQ_API_KEY=your_key_here
# optional
SYSTEM_PROMPT="You are a senior network security analyst."
```

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend**

```bash
npm install
npm run dev
```

Open http://localhost:3000. The frontend calls `http://localhost:8000` directly — that URL is hardcoded in `components/ui/file-upload.tsx`, so the backend must be on port 8000.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/uploadfile/` | Multipart `file`; returns `protocols`, `packet_data`, `total_data_size`, `stats`, `classification` |
| `POST` | `/generate-summary/` | JSON `{protocols, packet_data, total_data_size, classification}`; returns `{summary: [markdown]}` |

## Docker

```bash
docker build -t netnerve-v0 .
docker run --env-file .env -p 10000:10000 netnerve-v0
```

Two things in the committed Dockerfile need fixing before that build succeeds:

1. It copies the frontend from `/frontend/out`, which requires `output: 'export'` in `next.config.ts`. That option is not set, so `npm run build` writes `.next/` and the `COPY` step fails.
2. Even with a static export, the built frontend still calls `http://localhost:8000` from the browser, not the container's port 10000.

The image on Docker Hub may predate both issues.

## Deployment notes

- `render.yaml` deploys only the backend (`rootDir: backend`, gunicorn + uvicorn worker, port 10000).
- `vercel.json` currently redirects every path to `https://netnerve.online/`. The old `netnerve.vercel.app` demo no longer serves this code.

## Data handling

- The uploaded file is written to a UUID-named temporary file, parsed, and deleted in a `finally` block. It is not stored.
- Packet metadata, payload snippets and the deterministic findings are sent to the model provider to generate the report.
- There is no database, no account system and no retention in this version.

## What changed since V0

| V0 demo (this repo) | Production |
|---|---|
| Scapy `rdpcap()` | tshark primary parser, Scapy as fallback and for forensics sampling |
| Hand-written regex and heuristics only | Suricata 7.0 with the Emerging Threats Open ruleset, plus heuristics, anomaly checks, protocol validation and MITRE ATT&CK correlation |
| A single commercial LLM API | Managed AI APIs |
| 10 MB, `.pcap`/`.cap` | Free 2 MB / 500 packets, Pro 20 MB / 5,000, Forensics 50 MB / 15,000; `.pcapng` on Pro |
| No accounts | Clerk auth, Polar billing, shareable reports |
| Payload sent to the model | Payload and raw bytes stripped before any prompt |
| No export tooling | In-browser PCAP-to-CSV, IP extraction and sanitizer |

Current detection docs: https://netnerve.online/docs
Public teardowns with frame-level evidence: https://netnerve.online/analyses

## Attribution

If you write about this project, link the production site rather than the demo:

> NetNerve by Shubham Bhat — [netnerve.online](https://netnerve.online)

## License

MIT. See [LICENSE](./LICENSE).
