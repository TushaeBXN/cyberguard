#!/usr/bin/env python3
"""
Thin FastAPI server that wraps Kerrigan-Fantasma for CyberGuardAI.
Runs on localhost:7432. Killed when Electron closes.

Endpoints:
  POST /chat   { message, history } → { reply, blocked, model }
  GET  /status → { model, memory_count, uptime_s }
  POST /hunt   { path } → { findings, risk_score }
  POST /osint  { query } → { result }
"""

import sys
import os
import time
import json
import asyncio
from pathlib import Path

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
    print(f"[Server] Kerrigan modules not fully available: {e}")
    KERRIGAN_AVAILABLE = False

try:
    import ollama as _ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

app       = FastAPI(title="Kerrigan Server")
_start    = time.time()
_router   = None
_overmind = None
_memory   = None
_model    = "deepseek-coder:6.7b"


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
    print("Kerrigan server ready", flush=True)


@app.post("/chat")
async def chat(request: Request):
    body    = await request.json()
    message = body.get("message", "")
    history = body.get("history", [])

    # Safety gate first
    if _overmind:
        verdict = _overmind.verify(message)
        if getattr(verdict, "blocked", False) or (isinstance(verdict, dict) and verdict.get("blocked")):
            reason = getattr(verdict, "reason", verdict.get("reason", "blocked"))
            return JSONResponse({"reply": f"[Blocked by Overmind: {reason}]", "blocked": True, "model": "overmind"})

    # Retrieve relevant memory
    context = ""
    if _memory:
        try:
            hits = _memory.query(message, n=3)
            if hits:
                context = "\nRelevant prior findings:\n" + "\n".join(f"- {h}" for h in hits)
        except Exception:
            pass

    # Build prompt
    system = (
        "You are Kerrigan, a custom security AI built by Brian Tushae Thomas. "
        "You specialize in vulnerability research, exploit analysis, hardware security, "
        "and defensive tooling. You are running inside CyberGuardAI. "
        "Be concise and technical. For educational and authorized security research only."
    )

    messages = [{"role": "system", "content": system + context}]
    for h in history[-6:]:  # last 3 turns
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": message})

    # Call Ollama
    if OLLAMA_AVAILABLE:
        try:
            resp = _ollama.chat(model=_model, messages=messages)
            reply = resp["message"]["content"]
        except Exception as e:
            reply = f"[Ollama error: {e}. Is Ollama running with {_model}?]"
    else:
        reply = "[Ollama not installed. pip install ollama and pull a model.]"

    # Store to memory
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
        "kerrigan_ok":  KERRIGAN_AVAILABLE,
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


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=7432, log_level="warning")
