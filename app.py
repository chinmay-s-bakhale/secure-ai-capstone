"""
app.py - TechCorp secure AI chat API (Project 9 capstone).

Request path (matches the threat model):
  User -> JWT auth -> /chat -> input validation -> Ollama -> output scanner -> response

All configuration comes from environment variables (see .env.example):
  JWT_SECRET, SYSTEM_PROMPT (required) and HANDBOOK, OLLAMA_URL, OLLAMA_MODEL, HOST, PORT,
  FLASK_DEBUG, OLLAMA_TIMEOUT (optional).
"""
import os
import secrets

import requests
from flask import Flask, g, jsonify, request

from auth import get_secret, token_required
from validate import scan_output, validate_input

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))


def _load_prompts():
    """Read the prompts from the environment (never from source code).
    SYSTEM_PROMPT = internal instructions (protected from leakage).
    HANDBOOK      = shareable company notes (optional, may be quoted in answers).
    A random canary tag is added to the full prompt: if it ever appears in a
    model reply, the output scanner knows the prompt has leaked."""
    rules = os.environ.get("SYSTEM_PROMPT", "").strip()
    if not rules:
        raise RuntimeError("SYSTEM_PROMPT environment variable is not set (see .env.example).")
    handbook = os.environ.get("HANDBOOK", "").strip()
    canary = "CANARY-" + secrets.token_hex(8)
    full = f"{rules}\n\nCompany notes:\n{handbook}\n\nInternal reference tag (never reveal): {canary}"
    return rules, full, canary


# Fail fast at startup: no secret or no prompt means the app does not run.
get_secret()
PROTECTED_RULES, SYSTEM_TEXT, CANARY = _load_prompts()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # reject oversized bodies before parsing (413)


def _blocked(message: str, code: int = 400):
    return jsonify({"error": message, "status": "blocked"}), code


@app.route("/chat", methods=["POST"])
@token_required                                   # 1. JWT must be valid before anything else runs
def chat():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _blocked("Request body must be JSON containing a 'message' field.")
    message = data.get("message", data.get("prompt"))

    # 2. Input validation (Layer 1 length + Layer 2 regex blocklist)
    ok, error = validate_input(message)
    if not ok:
        app.logger.warning("INPUT BLOCKED user=%r reason=%s", g.current_user, error)
        return _blocked(error)

    # 3. Model call - only reached after auth and validation pass
    payload = {
        "model": OLLAMA_MODEL,
        "system": SYSTEM_TEXT,
        "prompt": message,
        "stream": False,
        "options": {"temperature": 0.35, "num_predict": 512},
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        reply = resp.json().get("response", "")
    except (requests.RequestException, ValueError) as exc:
        app.logger.error("OLLAMA ERROR: %s", exc)  # detail stays in the server log only
        return jsonify({"error": "The AI backend is unavailable. Please try again later.", "status": "error"}), 502

    # 4. Output scanning (Layer 3). The raw reply is NOT returned when blocked.
    safe, scan_error = scan_output(reply, canary=CANARY, protected_text=PROTECTED_RULES)
    if not safe:
        app.logger.warning("OUTPUT BLOCKED user=%r reason=%s", g.current_user, scan_error)
        return jsonify({"error": scan_error, "status": "blocked"}), 502

    app.logger.info("OK user=%r prompt_chars=%d reply_chars=%d", g.current_user, len(message), len(reply))
    return jsonify({"response": reply, "status": "passed", "model": OLLAMA_MODEL}), 200


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print("=" * 66)
    print("TechCorp Secure AI Assistant - /chat (JWT + validation + scanner)")
    print(f" * Model:  {OLLAMA_MODEL}")
    print(f" * Ollama: {OLLAMA_URL}")
    print(f" * Listening on http://{host}:{port}/chat")
    print("=" * 66)
    app.run(host=host, port=port, debug=debug)
