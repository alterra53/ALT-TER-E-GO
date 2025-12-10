# alterra_bot.py
# Nextcord bot + FastAPI backend (single-file)
# Env needed:
#  - TOKEN (Discord bot token)
#  - PUBLIC_URL (e.g. https://alterra-bot.onrender.com)
# Optional for better IP checks:
#  - IP_CHECK_URL (eg. https://api.ipcheck.example/check)  -- should accept ?ip=...
#  - IP_CHECK_KEY
# Files used (in repo root):
#  - config.json (guild config: verify_channel, verify_role)
#  - sessions.json (ephemeral sessions)
#  - verified_ips.json (map ip -> [ {guild_id, user_id, ts} ])
#  - banned_ips.json (map ip -> [ {guild_id, ts, reason} ])

import os
import json
import uuid
import time
import asyncio
from typing import Dict, Any
from pathlib import Path

# FastAPI + ASGI server
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn

# HTTP client
try:
    import httpx
except Exception:
    httpx = None

# Discord
import nextcord
from nextcord.ext import commands
from nextcord import Interaction, Colour

# --- Config / storage paths ---
BASE = Path(__file__).parent
CONFIG_FILE = BASE / "config.json"
SESSIONS_FILE = BASE / "sessions.json"
VERIFIED_IPS_FILE = BASE / "verified_ips.json"
BANNED_IPS_FILE = BASE / "banned_ips.json"

PUBLIC_URL = os.getenv("PUBLIC_URL")  # required
TOKEN = os.getenv("TOKEN")  # required

if not TOKEN:
    raise RuntimeError("TOKEN env missing")
if not PUBLIC_URL:
    raise RuntimeError("PUBLIC_URL env missing (e.g. https://alterra-bot.onrender.com)")

IP_CHECK_URL = os.getenv("IP_CHECK_URL")  # optional external IP check endpoint
IP_CHECK_KEY = os.getenv("IP_CHECK_KEY")  # optional key header

# --- helpers to load/save JSON ---
def load_json(path: Path, default):
    if not path.exists():
        path.write_text(json.dumps(default))
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default

def save_json(path: Path, data):
    path.write_text(json.dumps(data, indent=2))

# init storages
config = load_json(CONFIG_FILE, {})
sessions = load_json(SESSIONS_FILE, {})  # session_id -> dict
verified_ips = load_json(VERIFIED_IPS_FILE, {})  # ip -> list of records {guild_id,user_id,ts}
banned_ips = load_json(BANNED_IPS_FILE, {})  # ip -> list of records {guild_id,ts,reason}

# --- Nextcord bot setup ---
intents = nextcord.Intents.default()
intents.guilds = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)
app = FastAPI()

# small helpers for IP heuristics (when no external API available)
PRIVATE_PREFIXES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "169.254."
]
# crude list of suspicious provider names (ASN/org)
SUSPICIOUS_ASN_KEYWORDS = ["amazon", "aws", "digitalocean", "hetzner", "ovh", "vultr", "linode"]

# ------------ Utility functions ------------
def record_verified_ip(ip: str, guild_id: str, user_id: int):
    lst = verified_ips.get(ip, [])
    lst.append({"guild_id": guild_id, "user_id": user_id, "ts": int(time.time())})
    verified_ips[ip] = lst
    save_json(VERIFIED_IPS_FILE, verified_ips)

def record_banned_ip(ip: str, guild_id: str, reason: str = "ban"):
    lst = banned_ips.get(ip, [])
    lst.append({"guild_id": guild_id, "ts": int(time.time()), "reason": reason})
    banned_ips[ip] = lst
    save_json(BANNED_IPS_FILE, banned_ips)

def session_save():
    save_json(SESSIONS_FILE, sessions)

# basic IP checks when no external API: private/reserved + simple ASN heuristics
def basic_ip_checks(ip: str) -> Dict[str, Any]:
    # returns dict: {ok:bool, reason:str, details: {...}}
    lower = ip.strip()
    for p in PRIVATE_PREFIXES:
        if lower.startswith(p):
            return {"ok": False, "reason": "private_or_bogon", "details": {}}
    # crude check: if ip previously verified or banned (handled elsewhere)
    # no more we can do without external API
    return {"ok": True, "reason": "basic_ok", "details": {}}

async def external_ip_check(ip: str) -> Dict[str, Any]:
    # protocol for external API: expects IP in query param ?ip=...
    # and returns JSON with fields like "proxy": bool, "tor": bool, "hosting": bool, "org": str
    if not IP_CHECK_URL:
        return {"ok": True, "method": "none", "result": basic_ip_checks(ip)}
    client = None
    try:
        if httpx:
            async with httpx.AsyncClient(timeout=10) as client:
                headers = {}
                if IP_CHECK_KEY:
                    headers["Authorization"] = IP_CHECK_KEY
                r = await client.get(IP_CHECK_URL, params={"ip": ip}, headers=headers)
                data = r.json()
        else:
            import requests
            headers = {}
            if IP_CHECK_KEY:
                headers["Authorization"] = IP_CHECK_KEY
            r = requests.get(IP_CHECK_URL, params={"ip": ip}, headers=headers, timeout=10)
            data = r.json()
    except Exception as e:
        return {"ok": False, "method": "external_error", "error": str(e)}
    # normalize common fields
    proxy = bool(data.get("proxy") or data.get("is_proxy") or data.get("hosting") or data.get("vpn"))
    tor = bool(data.get("tor") or data.get("is_tor"))
    hosting = bool(data.get("hosting") or data.get("is_crawler"))
    org = data.get("org") or data.get("hostname") or data.get("isp") or ""
    # decide
    if proxy or tor or hosting:
        return {"ok": False, "method": "external", "reason": "proxy/tor/hosting", "details": {"proxy": proxy, "tor": tor, "hosting": hosting, "org": org}}
    # else ok
    return {"ok": True, "method": "external", "details": {"org": org}}

# get client IP from request
def get_client_ip(request: Request) -> str:
    # prefer X-Forwarded-For if present
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # may contain comma-separated list
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "0.0.0.0"

# ------------ FastAPI endpoints ------------
@app.get("/ping")
async def ping():
    return {"ok": True}

@app.get("/start", response_class=HTMLResponse)
async def start_verification(request: Request, session: str = None):
    if not session:
        raise HTTPException(status_code=400, detail="missing session")
    sess = sessions.get(session)
    if not sess:
        raise HTTPException(status_code=404, detail="invalid session")
    # check if session expired (15 min)
    now = int(time.time())
    if now - sess.get("created_at", 0) > 60 * 60:  # 60 min expiration
        raise HTTPException(status_code=410, detail="session expired")
    # get client ip
    ip = get_client_ip(request)
    guild_id = sess["guild_id"]
    user_id = sess["user_id"]

    # check banned ips
    if ip in banned_ips:
        for rec in banned_ips[ip]:
            if rec.get("guild_id") == guild_id:
                html = f"<html><body><h2>Access denied</h2><p>Your IP is associated with a ban in this server.</p></body></html>"
                return HTMLResponse(content=html, status_code=403)

    # check verified ips: if same ip already verified in same guild -> reject
    if ip in verified_ips:
        for rec in verified_ips[ip]:
            if rec.get("guild_id") == guild_id:
                html = f"<html><body><h2>Access denied</h2><p>An account from this IP is already verified on this server.</p></body></html>"
                return HTMLResponse(content=html, status_code=403)

    # do external ip check if configured
    ext = await external_ip_check(ip)
    if not ext.get("ok"):
        # if external errored, fall back to basic check result if available
        if ext.get("method") == "external" and ext.get("reason"):
            html = f"<html><body><h2>Access denied</h2><p>IP flagged as proxy/tor/hosting: {ext.get('details')}</p></body></html>"
            return HTMLResponse(content=html, status_code=403)
        elif ext.get("method") == "external_error":
            # if external fails, try basic heuristic
            basic = basic_ip_checks(ip)
            if not basic["ok"]:
                return HTMLResponse(content=f"<html><body><h2>Access denied</h2><p>{basic['reason']}</p></body></html>", status_code=403)
            # else proceed
        else:
            return HTMLResponse(content=f"<html><body><h2>Access denied</h2><p>IP check failed</p></body></html>", status_code=403)

    # if passed checks, redirect to captcha page
    return RedirectResponse(url=f"{PUBLIC_URL}/captcha?session={session}")

# simple captcha page (client-side simple arithmetic puzzle)
@app.get("/captcha", response_class=HTMLResponse)
async def captcha_get(session: str = None):
    if not session or session not in sessions:
        raise HTTPException(status_code=404, detail="invalid session")
    # generate simple arithmetic puzzle stored in session
    a = int(time.time()) % 10 + 2
    b = (int(uuid.uuid4().int % 10) % 9) + 1
    answer = a + b
    sessions[session]["captcha_answer"] = answer
    session_save()
    html = f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Alterra Puzzle</title></head>
      <body>
        <h2>Complete the puzzle</h2>
        <p>Solve the puzzle to prove you're human:</p>
        <p><strong>{a} + {b} = ?</strong></p>
        <form method="post" action="/captcha/submit">
          <input type="hidden" name="session" value="{session}" />
          <input type="number" name="answer" required />
          <button type="submit">Submit</button>
        </form>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)

@app.post("/captcha/submit", response_class=HTMLResponse)
async def captcha_post(session: str = Form(...), answer: int = Form(...)):
    sess = sessions.get(session)
    if not sess:
        raise HTTPException(status_code=404, detail="invalid session")
    expected = sess.get("captcha_answer")
    if expected is None:
        raise HTTPException(status_code=400, detail="no captcha")
    try:
        if int(answer) != int(expected):
            return HTMLResponse(content="<html><body><h2>Wrong answer</h2><p>Please go back and try again.</p></body></html>", status_code=403)
    except:
        return HTMLResponse(content="<html><body><h2>Invalid</h2></body></html>", status_code=400)

    # mark passed
    sess["captcha_passed"] = True
    sess["completed_at"] = int(time.time())
    session_save()

    # record verified ip for guild
    ip = sess.get("ip")  # we didn't store ip earlier, re-evaluate? We'll accept ip from last check flow: get no reliable way; so derive generic
    # better: we can accept ip from request, but this POST comes from user - we don't have request object here.
    # for safety, ignore ip record here — instead record by resolving via sessions' stored 'last_ip' if present.
    # We expect sessions[session]['last_ip'] set by start_verification when redirected; ensure that.
    # If not present, skip ip record but still assign role.
    last_ip = sess.get("last_ip")
    if last_ip:
        record_verified_ip(last_ip, sess["guild_id"], sess["user_id"])
    # asynchronously assign role via bot
    asyncio.create_task(async_assign_role(sess["guild_id"], sess["user_id"], session))

    html = "<html><body><h2>Success</h2><p>You may now return to Discord. Close this page.</p></body></html>"
    return HTMLResponse(content=html, status_code=200)

# modify start_verification to record last_ip in session (we can't access request in /captcha submit)
@app.get("/start_with_ip")
async def start_with_ip(request: Request, session: str = None):
    # helper endpoint - not used directly by bot, used by redirection to capture IP and redirect to /captcha
    if not session or session not in sessions:
        raise HTTPException(status_code=404, detail="invalid session")
    ip = get_client_ip(request)
    sessions[session]["last_ip"] = ip
    session_save()
    return RedirectResponse(url=f"{PUBLIC_URL}/captcha?session={session}")

# to keep compatibility, ensure /start populates last_ip too before redirecting
# We'll update the start_verification function above to set last_ip if possible.
# (But since request available in start_verification, we can set it there. Update:)
# NOTE: to avoid code duplication, we will set last_ip in start_verification above.
# (Implementation already has request arg and get_client_ip call; set sessions[...] below)
# --- To keep file coherent, we'll patch start_verification here programmatically by reassigning the function ---
# However simpler: replicate logic: override start_verification route by re-defining it using same path.
@app.get("/start", response_class=HTMLResponse)
async def start_verification(request: Request, session: str = None):
    # redeclared: same behavior, but also records last_ip
    if not session:
        raise HTTPException(status_code=400, detail="missing session")
    sess = sessions.get(session)
    if not sess:
        raise HTTPException(status_code=404, detail="invalid session")
    now = int(time.time())
    if now - sess.get("created_at", 0) > 60 * 60:
        raise HTTPException(status_code=410, detail="session expired")
    ip = get_client_ip(request)
    guild_id = sess["guild_id"]
    user_id = sess["user_id"]

    # record last_ip
    sess["last_ip"] = ip
    session_save()

    # banned check
    if ip in banned_ips:
        for rec in banned_ips[ip]:
            if rec.get("guild_id") == guild_id:
                html = f"<html><body><h2>Access denied</h2><p>Your IP is associated with a ban in this server.</p></body></html>"
                return HTMLResponse(content=html, status_code=403)

    # verified check
    if ip in verified_ips:
        for rec in verified_ips[ip]:
            if rec.get("guild_id") == guild_id:
                html = f"<html><body><h2>Access denied</h2><p>An account from this IP is already verified on this server.</p></body></html>"
                return HTMLResponse(content=html, status_code=403)

    ext = await external_ip_check(ip)
    if not ext.get("ok"):
        if ext.get("method") == "external" and ext.get("reason"):
            html = f"<html><body><h2>Access denied</h2><p>IP flagged as proxy/tor/hosting: {ext.get('details')}</p></body></html>"
            return HTMLResponse(content=html, status_code=403)
        elif ext.get("method") == "external_error":
            basic = basic_ip_checks(ip)
            if not basic["ok"]:
                return HTMLResponse(content=f"<html><body><h2>Access denied</h2><p>{basic['reason']}</p></body></html>", status_code=403)
        else:
            return HTMLResponse(content=f"<html><body><h2>Access denied</h2><p>IP check failed</p></body></html>", status_code=403)

    return RedirectResponse(url=f"{PUBLIC_URL}/captcha?session={session}")

# ------------ Bot <-> web integration ------------
# Create session when user presses verify button
class VerifyButton(nextcord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @nextcord.ui.button(label="Verify", style=nextcord.ButtonStyle.primary, emoji="✔️", custom_id="alterra_verify_btn_v2")
    async def verify(self, button, interaction: Interaction):
        # create session
        sid = str(uuid.uuid4())
        guild_id = str(interaction.guild.id)
        sessions[sid] = {
            "session_id": sid,
            "guild_id": guild_id,
            "user_id": interaction.user.id,
            "created_at": int(time.time()),
            "captcha_passed": False
        }
        session_save()
        link = f"{PUBLIC_URL}/start?session={sid}"
        # ephemeral link only visible to user
        await interaction.response.send_message(f"Open this link to continue verification (private):\n{link}", ephemeral=True)

# async role assignment called after captcha passed
async def async_assign_role(guild_id: str, user_id: int, session_id: str):
    await bot.wait_until_ready()
    try:
        guild_obj = bot.get_guild(int(guild_id))
        if not guild_obj:
            print("[ASSIGN] guild not found", guild_id)
            return
        cfg = config.get(guild_id, {})
        role_id = cfg.get("verify_role")
        if not role_id:
            print("[ASSIGN] role not configured for guild", guild_id)
            return
        member = guild_obj.get_member(int(user_id))
        if not member:
            print("[ASSIGN] member not found in guild", user_id)
            return
        role = guild_obj.get_role(int(role_id))
        if not role:
            print("[ASSIGN] role object missing", role_id)
            return
        await member.add_roles(role, reason="Alterra verification (web captcha)")
        # DM the user
        try:
            await member.send("Well done. Verification complete.")
        except Exception:
            # send in verify channel if DM fails
            chan_id = config.get(guild_id, {}).get("verify_channel")
            if chan_id:
                ch = guild_obj.get_channel(int(chan_id))
                if ch:
                    await ch.send(f"<@{user_id}> Well done. Verification complete.")
        # record verified ip (if available)
        sess = sessions.get(session_id)
        if sess:
            ip = sess.get("last_ip")
            if ip:
                record_verified_ip(ip, guild_id, user_id)
            sess["role_assigned"] = True
            session_save()
    except Exception as e:
        print("[ASSIGN] error", e)

# ------------ Slash commands and setup message ------------
@bot.slash_command(name="setup-channel", description="Set the verification channel.")
async def setup_channel(interaction: Interaction):
    guild_id = str(interaction.guild.id)
    config[guild_id] = config.get(guild_id, {})
    config[guild_id]["verify_channel"] = interaction.channel.id
    save_json(CONFIG_FILE, config)
    await interaction.response.send_message(f"Verification channel set to: <#{interaction.channel.id}>", ephemeral=True)

@bot.slash_command(name="setup-role", description="Select role to give after verification.")
async def setup_role(interaction: Interaction, role: nextcord.Role):
    guild_id = str(interaction.guild.id)
    config[guild_id] = config.get(guild_id, {})
    config[guild_id]["verify_role"] = role.id
    save_json(CONFIG_FILE, config)
    await interaction.response.send_message(f"Verification role set to: **{role.name}**", ephemeral=True)

@bot.slash_command(name="setup-verify", description="Deploy verification embed with button.")
async def setup_verify(interaction: Interaction):
    guild_id = str(interaction.guild.id)
    if guild_id not in config or "verify_channel" not in config[guild_id]:
        return await interaction.response.send_message("Missing setup: channel and role must be configured.", ephemeral=True)
    channel_id = config[guild_id]["verify_channel"]
    channel = interaction.guild.get_channel(channel_id)
    if not channel:
        return await interaction.response.send_message("Channel missing or invalid.", ephemeral=True)
    embed = nextcord.Embed(
        title="Alterra Verification",
        description="Please complete this verification to be a member of the server.",
        colour=Colour.orange()
    )
    view = VerifyButton()
    await channel.send(embed=embed, view=view)
    await interaction.response.send_message(f"Verification message deployed in <#{channel.id}>.", ephemeral=True)

# on_ready: register persistent view
@bot.event
async def on_ready():
    bot.add_view(VerifyButton())
    print(f"[BOT READY] {bot.user} (id: {bot.user.id})")

# run both FastAPI and bot
def start_api():
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

if __name__ == "__main__":
    # run API in background thread, then bot in main thread (uvicorn in thread -> bot.run)
    import threading
    t = threading.Thread(target=start_api, daemon=True)
    t.start()
    bot.run(TOKEN)
