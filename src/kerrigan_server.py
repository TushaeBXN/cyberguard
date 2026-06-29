#!/usr/bin/env python3
"""
CyberGuard AI backend — FastAPI server on localhost:7432.
Killed when Electron closes.

Endpoints:
  POST /chat   { message, history } → { reply, blocked, model }
  GET  /status → { model, memory_count, uptime_s }
  POST /hunt   { path } → { findings, risk_score }
"""

import sys
import os
import time
import json
import asyncio
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "")
DB_NAME = os.environ.get("DB_NAME", "kerrigan_db")

# ── Add kerrigan-fantasma to path ─────────────────────────────────────────────
KERRIGAN_DIR = os.environ.get("KERRIGAN_PATH", str(Path(__file__).parent))
sys.path.insert(0, KERRIGAN_DIR)
os.chdir(KERRIGAN_DIR)

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn

# ── Lazy kerrigan imports (don't crash if deps missing) ──────────────────────
try:
    from router.abathur import AbathurRouter
    from verifier.overmind import Overmind
    from memory.creep import Creep
    KERRIGAN_AVAILABLE = True
except Exception as e:
    print(f"[Server] AI modules not fully available: {e}")
    KERRIGAN_AVAILABLE = False

try:
    import ollama as _ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

@asynccontextmanager
async def lifespan(app):
    _init()
    _ensure_tables()
    _ensure_conversations_table()
    asyncio.create_task(_ssh_honeypot())
    asyncio.create_task(_web_honeypot())
    asyncio.create_task(_db_honeypot())
    print("CyberGuard AI server ready", flush=True)
    yield

app       = FastAPI(title="CyberGuard AI Server", lifespan=lifespan)
_start    = time.time()
_router   = None
_overmind = None
_memory   = None
_model    = "deepseek-coder:6.7b"

# ── MySQL direct connection ────────────────────────────────────────────────────
import hashlib

def _get_db():
    try:
        import mysql.connector
        return mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
    except Exception as e:
        print(f"[DB] MySQL unavailable: {e}")
        return None

def _ensure_tables():
    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS honeypot_events (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                honeypot_type VARCHAR(16) NOT NULL,
                attacker_ip   VARCHAR(64) NOT NULL,
                attacker_port INT,
                payload       TEXT,
                created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_type (honeypot_type),
                INDEX idx_ip   (attacker_ip),
                INDEX idx_time (created_at)
            )
        """)
        conn.commit()
    except Exception as e:
        print(f"[DB] honeypot_events table error: {e}")
    finally:
        conn.close()

def _log_honeypot(honeypot_type, attacker_ip, attacker_port, payload=""):
    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO honeypot_events (honeypot_type, attacker_ip, attacker_port, payload) VALUES (%s,%s,%s,%s)",
            (honeypot_type, attacker_ip, int(attacker_port or 0), payload[:1000])
        )
        conn.commit()
        # Auto-feed into Kerrigan memory
        _save_memory_to_db(
            f"Honeypot hit [{honeypot_type}]: attacker {attacker_ip}:{attacker_port} — {payload[:200]}",
            expert="honeypot",
            tags=f"honeypot,{honeypot_type},{attacker_ip}"
        )
    except Exception as e:
        print(f"[DB] honeypot log error: {e}")
    finally:
        conn.close()

def _ensure_conversations_table():
    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id         INT AUTO_INCREMENT PRIMARY KEY,
                conv_id    VARCHAR(32) NOT NULL,
                role       VARCHAR(16) NOT NULL,
                content    TEXT NOT NULL,
                model      VARCHAR(64),
                blocked    TINYINT(1) DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_conv (conv_id),
                INDEX idx_created (created_at)
            )
        """)
        conn.commit()
    except Exception as e:
        print(f"[DB] Table create error: {e}")
    finally:
        conn.close()

def _save_to_db(conv_id, role, content, model=None, blocked=False):
    conn = _get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO conversations (conv_id, role, content, model, blocked) VALUES (%s,%s,%s,%s,%s)",
            (conv_id, role, content, model, int(blocked))
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Save error: {e}")
    finally:
        conn.close()

def _save_memory_to_db(content, expert="cyberguard_chat", tags=None):
    conn = _get_db()
    if not conn: return
    try:
        mem_id = hashlib.md5(content.encode()).hexdigest()
        cur = conn.cursor()
        cur.execute(
            "INSERT IGNORE INTO memories (memory_id, content, expert, tags, created_at) VALUES (%s,%s,%s,%s,NOW())",
            (mem_id, content, expert, tags)
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Memory save error: {e}")
    finally:
        conn.close()


def _init():
    global _router, _overmind, _memory
    if not KERRIGAN_AVAILABLE:
        return
    try:
        _overmind = Overmind()
    except Exception as e:
        print(f"[Server] Overmind init error: {e}")
    try:
        _memory = Creep()
    except Exception as e:
        print(f"[Server] Creep init error: {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

# ── Real Honeypots ─────────────────────────────────────────────────────────────

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
HTTP_TRAP  = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n"
MYSQL_GREETING = (
    b"\x4a\x00\x00\x00"
    b"\x0a"
    b"8.0.32\x00"
    b"\x01\x00\x00\x00"
    b"\x52\x7d\x1f\x29\x65\x43\x41\x48\x00"
    b"\xff\xf7"
    b"\x21"
    b"\x02\x00"
    b"\xff\x81"
    b"\x15"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x7e\x31\x3e\x1c\x58\x58\x36\x73\x6a\x49\x5a\x55\x00"
    b"mysql_native_password\x00"
)

async def _ssh_honeypot(host="0.0.0.0", port=2222):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            writer.write(SSH_BANNER)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=10)
            payload = data.decode("utf-8", errors="replace").strip()
        except Exception:
            payload = ""
        finally:
            writer.close()
        print(f"[Honeypot-SSH] {ip}:{p} — {repr(payload[:80])}")
        _log_honeypot("ssh", ip, p, payload)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] SSH listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] SSH failed on {port}: {e}")

async def _web_honeypot(host="0.0.0.0", port=8080):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=10)
            payload = data.decode("utf-8", errors="replace")
            first_line = payload.split("\n")[0].strip()
            writer.write(HTTP_TRAP)
            await writer.drain()
        except Exception:
            first_line = ""
        finally:
            writer.close()
        print(f"[Honeypot-Web] {ip}:{p} — {first_line[:120]}")
        _log_honeypot("web", ip, p, first_line)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] Web listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] Web failed on {port}: {e}")

async def _db_honeypot(host="0.0.0.0", port=3307):
    async def handle(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip, p = peer[0], peer[1]
        try:
            writer.write(MYSQL_GREETING)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=10)
            payload = data.hex()[:120]
        except Exception:
            payload = ""
        finally:
            writer.close()
        print(f"[Honeypot-DB] {ip}:{p} — {payload}")
        _log_honeypot("database", ip, p, payload)
    try:
        srv = await asyncio.start_server(handle, host, port)
        print(f"[Honeypot] Database listening on {port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[Honeypot] Database failed on {port}: {e}")


@app.post("/chat")
async def chat(request: Request):
    body    = await request.json()
    message     = body.get("message", "")
    history     = body.get("history", [])
    system_ctx  = body.get("system_context", "")

    # Safety gate first
    if _overmind:
        verdict = _overmind.verify(message)
        if getattr(verdict, "blocked", False) or (isinstance(verdict, dict) and verdict.get("blocked")):
            reason = getattr(verdict, "reason", verdict.get("reason", "blocked"))
            return JSONResponse({"reply": f"[Blocked by Overmind: {reason}]", "blocked": True, "model": "overmind"})

    # Retrieve relevant memory
    mem_context = ""
    if _memory:
        try:
            hits = _memory.query(message, n=3)
            if hits:
                mem_context = "\nRelevant prior findings:\n" + "\n".join(f"- {h}" for h in hits)
        except Exception:
            pass

    # Build prompt
    system = (
        "You are Kerrigan, a security AI built into CyberGuard AI by Brian Tushae Thomas. "
        "You have DIRECT ACCESS to this machine's live security telemetry — it is injected below. "
        "NEVER say you cannot access the system or lack real-time data. You have it. Use it. "
        "Answer specifically about THIS machine using the data provided. "
        "Be direct, technical, and concise. No disclaimers. No generic advice unless asked.\n"
    )
    if system_ctx:
        system += "\n=== LIVE SYSTEM STATE ===\n" + system_ctx + "\n=== END SYSTEM STATE ===\n"
    if mem_context:
        system += "\n=== PRIOR FINDINGS ===\n" + mem_context + "\n========================\n"

    messages = [{"role": "system", "content": system}]
    for h in history[-6:]:  # last 3 turns
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": message})

    # Generate a stable conversation ID from the first user message
    conv_id = hashlib.md5(message[:64].encode()).hexdigest()[:16]

    # Save user message to MySQL
    _save_to_db(conv_id, "user", message, model=_model)

    # Call Ollama
    if OLLAMA_AVAILABLE:
        try:
            resp = _ollama.chat(model=_model, messages=messages)
            reply = resp["message"]["content"]
        except Exception as e:
            reply = f"[Ollama error: {e}. Is Ollama running with {_model}?]"
    else:
        reply = "[Ollama not installed. pip install ollama and pull a model.]"

    # Save assistant reply to MySQL
    _save_to_db(conv_id, "assistant", reply, model=_model)

    # Save as memory entry so it appears in Memories tab
    _save_memory_to_db(
        f"Q: {message}\nA: {reply[:400]}",
        expert="cyberguard_chat",
        tags="chat,cyberguard"
    )

    # Store to ChromaDB if available
    if _memory:
        try:
            _memory.store(f"Q: {message}\nA: {reply[:300]}", metadata={"source": "cyberguard_chat"})
        except Exception:
            pass

    return JSONResponse({"reply": reply, "blocked": False, "model": _model})


@app.get("/status")
async def status():
    mem_count = 0
    if _memory:
        try:
            mem_count = _memory.count()
        except Exception:
            pass
    return {
        "model":        _model,
        "memory_count": mem_count,
        "uptime_s":     round(time.time() - _start, 1),
        "ai_ok":        KERRIGAN_AVAILABLE,
        "ollama_ok":    OLLAMA_AVAILABLE,
    }


@app.post("/hunt")
async def hunt(request: Request):
    body       = await request.json()
    target_path = body.get("path", ".")
    try:
        from loop.hunter import ThreatHunter
        hunter   = ThreatHunter(target_path)
        findings = hunter.scan()
        return {
            "findings":   [f.to_dict() for f in findings[:50]],
            "risk_score": hunter.risk_score(),
            "total":      len(findings),
        }
    except Exception as e:
        return {"error": str(e), "findings": [], "risk_score": 0}


# ── Real Pen Testing ──────────────────────────────────────────────────────────

@app.get("/pentest/headers")
async def pentest_headers(url: str = "http://localhost"):
    import requests as req
    results = []
    try:
        r = req.get(url, timeout=5, verify=False, allow_redirects=True)
        headers = r.headers
        checks = [
            ("Strict-Transport-Security", "HSTS", "Forces HTTPS connections"),
            ("X-Frame-Options", "Clickjacking", "Prevents iframe embedding"),
            ("X-Content-Type-Options", "MIME Sniff", "Blocks MIME type sniffing"),
            ("Content-Security-Policy", "CSP", "Controls resource loading"),
            ("X-XSS-Protection", "XSS Filter", "Legacy XSS filter"),
            ("Referrer-Policy", "Referrer", "Controls referrer info"),
            ("Permissions-Policy", "Permissions", "Controls browser features"),
        ]
        for hdr, name, desc in checks:
            present = hdr in headers
            results.append({
                "header": hdr, "name": name, "desc": desc,
                "present": present, "value": headers.get(hdr, ""),
                "status": "pass" if present else "fail"
            })
        return {"url": url, "status_code": r.status_code, "checks": results, "server": headers.get("Server","unknown")}
    except Exception as e:
        return {"url": url, "error": str(e), "checks": results}


@app.post("/pentest/portscan")
async def pentest_portscan(request: Request):
    body   = await request.json()
    target = body.get("target", "127.0.0.1")
    ports  = body.get("ports", [21,22,23,25,53,80,443,3306,3307,5432,6379,8080,8443,27017])
    open_ports = []
    async def check(port):
        try:
            conn = asyncio.open_connection(target, port)
            r, w = await asyncio.wait_for(conn, timeout=1.0)
            banner = ""
            try: banner = (await asyncio.wait_for(r.read(256), timeout=1.0)).decode("utf-8","replace").strip()[:80]
            except: pass
            w.close()
            return {"port": port, "state": "open", "banner": banner}
        except: return {"port": port, "state": "closed", "banner": ""}
    results = await asyncio.gather(*[check(p) for p in ports])
    open_ports = [r for r in results if r["state"] == "open"]
    return {"target": target, "scanned": len(ports), "open": open_ports, "open_count": len(open_ports)}


@app.get("/pentest/ssl")
async def pentest_ssl(host: str = "localhost", port: int = 443):
    import subprocess
    try:
        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-brief"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8,
                          input="Q\n")
        output = r.stdout + r.stderr
        checks = []
        checks.append({"check":"Connection","status":"pass" if "CONNECTED" in output else "fail","detail":""})
        checks.append({"check":"TLS 1.3","status":"pass" if "TLSv1.3" in output else "warn","detail":output.split("Protocol")[1][:20].strip() if "Protocol" in output else ""})
        checks.append({"check":"Certificate","status":"pass" if "Verification" in output else "warn","detail":""})
        for weak in ["RC4","DES","NULL","EXPORT","MD5","SSLv2","SSLv3"]:
            if weak in output:
                checks.append({"check":f"Weak cipher: {weak}","status":"fail","detail":f"{weak} detected in negotiation"})
        return {"host": host, "port": port, "checks": checks, "raw": output[:500]}
    except Exception as e:
        return {"host": host, "port": port, "checks": [], "error": str(e)}


@app.get("/pentest/ssh-audit")
async def pentest_ssh_audit():
    import subprocess, glob
    results = []
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.exists():
        return {"keys": [], "error": "No ~/.ssh directory found"}
    for f in ssh_dir.iterdir():
        if f.suffix in (".pub",) or f.name in ("known_hosts","authorized_keys","config"):
            continue
        if not f.is_file(): continue
        try:
            r = subprocess.run(["ssh-keygen","-l","-f",str(f)], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                parts = r.stdout.strip().split()
                bits = int(parts[0]) if parts else 0
                key_type = parts[-1].strip("()") if parts else "unknown"
                status = "pass" if bits >= 3072 or key_type in ("ED25519","ECDSA") else "warn" if bits >= 2048 else "fail"
                results.append({"file": f.name, "bits": bits, "type": key_type, "status": status,
                               "fingerprint": parts[1] if len(parts)>1 else ""})
        except Exception as e:
            results.append({"file": f.name, "bits": 0, "type": "unknown", "status": "warn", "error": str(e)})
    pub_keys = list(ssh_dir.glob("*.pub"))
    return {"keys": results, "key_count": len(results), "pubkey_count": len(pub_keys), "ssh_dir": str(ssh_dir)}


# ── Real Network Map ───────────────────────────────────────────────────────────

@app.get("/network/arp")
async def network_arp():
    import subprocess, re
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        devices = []
        for line in r.stdout.splitlines():
            m = re.match(r'\?\s+\(([^)]+)\)\s+at\s+(\S+)\s+on\s+(\S+)', line)
            if not m: continue
            ip, mac, iface = m.group(1), m.group(2), m.group(3)
            if mac == "(incomplete)": continue
            devices.append({"ip": ip, "mac": mac, "interface": iface, "name": ip})
        return {"devices": devices, "count": len(devices)}
    except Exception as e:
        return {"devices": [], "error": str(e)}

@app.get("/network/routes")
async def network_routes():
    import subprocess, re
    try:
        r = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=10)
        routes = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and re.match(r'\d+\.\d+', parts[0]):
                routes.append({"destination": parts[0], "gateway": parts[1], "flags": parts[2], "interface": parts[3] if len(parts)>3 else ""})
        return {"routes": routes[:30]}
    except Exception as e:
        return {"routes": [], "error": str(e)}


# ── Real CVE Lookup ────────────────────────────────────────────────────────────

@app.get("/scan/cve")
async def scan_cve(q: str = "macos"):
    import requests as req
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}&resultsPerPage=10"
        r = req.get(url, timeout=10, headers={"User-Agent": "CyberGuardAI/1.0"})
        data = r.json()
        vulns = []
        for item in data.get("vulnerabilities", []):
            cve  = item.get("cve", {})
            cvss = 0
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData",{}).get("baseScore", 0)
                    break
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en": desc = d.get("value",""); break
            vulns.append({
                "id": cve.get("id",""),
                "score": cvss,
                "severity": "critical" if cvss>=9 else "high" if cvss>=7 else "medium" if cvss>=4 else "low",
                "description": desc[:200],
                "published": cve.get("published","")[:10],
            })
        return {"query": q, "total": data.get("totalResults", 0), "vulns": vulns}
    except Exception as e:
        return {"query": q, "total": 0, "vulns": [], "error": str(e)}


# ── Real AI Patcher Status ─────────────────────────────────────────────────────

@app.get("/patcher/status")
async def patcher_status():
    import glob
    stage4_count = len(list(Path(KERRIGAN_DIR).glob("data/stage4/*.jsonl")))
    stage4_examples = 0
    for f in Path(KERRIGAN_DIR).glob("data/stage4/*.jsonl"):
        try: stage4_examples += sum(1 for _ in open(f))
        except: pass
    adaptive_rules = 0
    adaptive_path = Path(KERRIGAN_DIR) / "data" / "adaptive_defense.jsonl"
    if adaptive_path.exists():
        try: adaptive_rules = sum(1 for _ in open(adaptive_path))
        except: pass
    conn = _get_db()
    db_crashes, db_sessions, total_crashes = 0, 0, 0
    if conn:
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT COUNT(*) as n FROM crashes")
            db_crashes = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) as n FROM sessions")
            db_sessions = cur.fetchone()["n"]
            cur.execute("SELECT COALESCE(SUM(total_crashes),0) as n FROM sessions")
            total_crashes = cur.fetchone()["n"] or 0
        except: pass
        finally: conn.close()
    pqc_ok = (Path(KERRIGAN_DIR) / "keys").exists()
    return {
        "stage4_files": stage4_count,
        "stage4_examples": stage4_examples,
        "adaptive_rules": adaptive_rules,
        "db_crashes": db_crashes,
        "db_sessions": db_sessions,
        "total_crashes_found": int(total_crashes),
        "pqc_keys_exist": pqc_ok,
        "kerrigan_available": KERRIGAN_AVAILABLE,
    }


@app.get("/honeypot/counts")
async def honeypot_counts():
    conn = _get_db()
    if not conn:
        return {"ssh": 0, "web": 0, "database": 0, "total": 0, "recent": []}
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT honeypot_type, COUNT(*) as cnt
            FROM honeypot_events GROUP BY honeypot_type
        """)
        rows = {r["honeypot_type"]: r["cnt"] for r in cur.fetchall()}
        cur.execute("""
            SELECT honeypot_type, attacker_ip, attacker_port, payload, created_at
            FROM honeypot_events ORDER BY created_at DESC LIMIT 20
        """)
        recent = cur.fetchall()
        for r in recent:
            if r.get("created_at"): r["created_at"] = r["created_at"].isoformat()
        return {
            "ssh":      rows.get("ssh", 0),
            "web":      rows.get("web", 0),
            "database": rows.get("database", 0),
            "total":    sum(rows.values()),
            "recent":   recent,
        }
    except Exception as e:
        return {"ssh": 0, "web": 0, "database": 0, "total": 0, "recent": [], "error": str(e)}
    finally:
        conn.close()


@app.get("/db/conversations")
async def db_conversations(limit: int = 50):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM conversations ORDER BY created_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            if r.get("created_at"): r["created_at"] = r["created_at"].isoformat()
        return {"conversations": rows}
    except Exception as e:
        return {"conversations": [], "error": str(e)}


@app.get("/db/memories")
async def db_memories(limit: int = 20, offset: int = 0):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, content, expert, tags, created_at FROM memories ORDER BY created_at DESC LIMIT %s OFFSET %s", (limit, offset))
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) as total FROM memories")
        total = cur.fetchone()["total"]
        conn.close()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return {"memories": rows, "total": total}
    except Exception as e:
        return {"memories": [], "total": 0, "error": str(e)}

@app.get("/db/crashes")
async def db_crashes(limit: int = 20):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM crashes ORDER BY created_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return {"crashes": rows}
    except Exception as e:
        return {"crashes": [], "error": str(e)}

@app.get("/db/sessions")
async def db_sessions(limit: int = 10):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            for k in ["started_at","ended_at"]:
                if r.get(k): r[k] = r[k].isoformat()
        return {"sessions": rows}
    except Exception as e:
        return {"sessions": [], "error": str(e)}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=7432, log_level="warning")
