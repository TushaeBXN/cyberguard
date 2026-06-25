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

app       = FastAPI(title="CyberGuard AI Server")
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

@app.on_event("startup")
async def on_startup():
    _init()
    _ensure_conversations_table()
    print("CyberGuard AI server ready", flush=True)


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
