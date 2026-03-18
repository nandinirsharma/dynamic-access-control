# app.py
from flask import Flask, request, jsonify, g, render_template
from flask_cors import CORS
from functools import wraps
import logging
import os
import sqlite3
from datetime import datetime, timezone, timedelta

# Import DB helpers (we rely on DB_PATH and init_db)
from db import (
    create_user,
    get_user_by_username,
    add_or_update_device,
    get_devices_for_user,
    record_login_event,
    log_access,
    get_recent_access_count,
    create_session,
    get_session_by_jti,
    revoke_session_by_jti,
    init_db,
    DB_PATH
)

from auth import hash_password, verify_password, create_token, decode_token, get_jti_from_token, ACCESS_TOKEN_EXP_MINUTES, JWT_SECRET
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

# risk_engine and opa_client are optional
try:
    from risk_engine import compute_risk
except Exception:
    compute_risk = None
try:
    from opa_client import query_opa
except Exception:
    query_opa = None

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

logging.info("Using DB file: %s", DB_PATH)
init_db()

# ---------------------------
# Helper decorator to require JWT + server-side session checks
# ---------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"error": "Missing token"}), 401

        # 1) Try to decode token (verify signature + expiry)
        try:
            payload = decode_token(token)  # raises ExpiredSignatureError if expired
            username = payload.get("sub")
            role = payload.get("role", "user")
            jti = payload.get("jti")
        except ExpiredSignatureError:
            return jsonify({"error": "SESSION TIMEOUT...EXPIRED TOKEN"}), 401
        except InvalidTokenError as e:
            return jsonify({"error": "INVALID TOKEN", "details": str(e)}), 401
        except Exception as e:
            logging.warning("Token decode failed: %s", e)
            return jsonify({"error": "INVALID TOKEN", "details": str(e)}), 401

        # 2) Check server-side session (by jti)
        try:
            sess = get_session_by_jti(jti)
            if not sess:
                return jsonify({"error": "INVALID TOKEN - session not found. Please login again."}), 401
            if int(sess.get("revoked", 0)):
                return jsonify({"error": "INVALID TOKEN - session revoked (logout). Please login again."}), 401
            # double-check expiry from sessions table
            try:
                exp_iso = sess.get("expires_at")
                if exp_iso:
                    exp_dt = datetime.fromisoformat(exp_iso)
                    if exp_dt.tzinfo is None:
                        # assume UTC
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) >= exp_dt:
                        return jsonify({"error": "SESSION TIMEOUT...EXPIRED TOKEN"}), 401
            except Exception:
                # if parse fails, ignore (JWT decode already checked expiry)
                pass
            # ensure user still exists
            user = get_user_by_username(username)
            if not user:
                return jsonify({"error": "User no longer exists"}), 401
            g.user = {"id": user["id"], "username": user["username"], "role": role}
            g.session = sess
        except Exception as e:
            logging.exception("session lookup failed")
            return jsonify({"error": "INVALID TOKEN", "details": str(e)}), 401

        return f(*args, **kwargs)
    return decorated


# ---------------------------
# Auth endpoints
# ---------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username_raw = data.get("username")
    password = data.get("password")
    device_type = data.get("device_type") or request.headers.get("X-Device-Type")
    reg_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if not username_raw or not password:
        return jsonify({"error": "username & password required"}), 400

    # Normalize username consistently
    username = str(username_raw).strip().lower()

    # check existing
    existing = get_user_by_username(username)
    if existing:
        return jsonify({"error": "username exists"}), 409

    phash = hash_password(password)
    try:
        uid = create_user(username, phash)
    except Exception as e:
        logging.exception("create_user failed")
        return jsonify({"error": "internal error", "details": str(e)}), 500
    if not uid:
        return jsonify({"error": "username exists"}), 409

    # persist registration_ip/device_type into users table if columns exist
    try:
        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
        cur.execute("UPDATE users SET registration_ip=?, device_type=? WHERE id=?", (reg_ip, device_type, uid))
        conn.commit(); conn.close()
    except Exception:
        logging.exception("failed to update user registration info (non-fatal)")

    # Insert the registration device into devices table so first login is recognized as the same device
    try:
        add_or_update_device(uid, (device_type or "unknown").strip().lower(), compliance_score=100)
    except Exception:
        logging.exception("add_or_update_device failed (non-fatal)")

    # log registration in access_logs (for audit)
    try:
        log_access(user_id=uid, username=username, resource="register",
                   ip=reg_ip, device_type=device_type, user_agent=request.headers.get("User-Agent", "unknown"),
                   risk_score=0, risk_level="INFO", decision="CREATE", details="user_registered")
    except Exception:
        logging.exception("log_access failed for register (non-fatal)")

    return jsonify({"message": "user created", "username": username}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username_raw = data.get("username")
    password = data.get("password")
    device_type = (data.get("device_type") or request.headers.get("X-Device-Type") or "").strip().lower()
    ip_override = data.get("ip")
    client_ip = ip_override or request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "unknown")

    if not username_raw or not password:
        return jsonify({"error": "username & password required"}), 400

    username = str(username_raw).strip().lower()
    user = get_user_by_username(username)

    # Unknown user -> log and return 401
    if not user:
        try:
            log_access(user_id=None, username=username or "unknown", resource="login", ip=client_ip,
                       device_type=device_type, user_agent=user_agent, risk_score=100, risk_level="HIGH", decision="DENY",
                       details="invalid_username")
        except Exception:
            logging.exception("log_access failed for invalid username (non-fatal)")

        try:
            record_login_event(None, username or "unknown", client_ip, device_type, user_agent, success=0)
        except Exception:
            logging.exception("record_login_event failed (non-fatal)")
        return jsonify({"error": "invalid credentials"}), 401

    # Wrong password -> log and return 401
    if not verify_password(password, user["password_hash"]):
        try:
            log_access(user_id=user["id"], username=username, resource="login", ip=client_ip,
                       device_type=device_type, user_agent=user_agent, risk_score=100, risk_level="HIGH", decision="DENY",
                       details="invalid_password")
        except Exception:
            logging.exception("log_access failed for invalid password (non-fatal)")

        try:
            record_login_event(user["id"], username, client_ip, device_type, user_agent, success=0)
        except Exception:
            logging.exception("record_login_event failed (non-fatal)")
        return jsonify({"error": "invalid credentials"}), 401

    # Successful auth -> check device match against stored devices/registration
    try:
        devices = get_devices_for_user(user["id"]) or []
    except Exception:
        logging.exception("get_devices_for_user failed")
        devices = []

    device_matched = False
    try:
        incoming_fp = device_type or ""
        # check devices table
        for d in devices:
            fp = str(d.get("device_fingerprint", "")).strip().lower()
            if fp and fp == incoming_fp:
                device_matched = True
                break
        # fallback: check users.registration device_type
        if not device_matched:
            try:
                reg_device = user.get("device_type")
                if reg_device and str(reg_device).strip().lower() == incoming_fp:
                    device_matched = True
            except Exception:
                pass
    except Exception:
        logging.exception("device matching check failed (non-fatal)")

    # Issue token (short-lived)
    token = create_token(username, "user")

    # Extract jti and exp to store session server-side
    try:
        # get payload without verifying signature (safe since token just issued)
        payload = jwt.decode(token, JWT_SECRET, algorithms=[jwt.get_default_algorithm()], options={"verify_signature": False, "verify_exp": False})
        jti = payload.get("jti")
        exp_ts = payload.get("exp")
        issued_at = datetime.now(timezone.utc).isoformat()
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat() if exp_ts else (datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXP_MINUTES)).isoformat()
        try:
            create_session(user["id"], jti, token, issued_at, expires_at)
        except Exception:
            logging.exception("create_session failed (non-fatal)")
    except Exception:
        # fallback: try helper to read jti
        try:
            jti = get_jti_from_token(token)
            create_session(user["id"], jti, token, datetime.now(timezone.utc).isoformat(), (datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXP_MINUTES)).isoformat())
        except Exception:
            logging.exception("session store fallback failed")

    # record successful login with token
    try:
        record_login_event(user["id"], username, client_ip, device_type, user_agent, success=1, access_token=token)
    except Exception:
        logging.exception("record_login_event failed for successful login (non-fatal)")

    # update/create device record so future logins are recognized
    try:
        add_or_update_device(user["id"], device_type or "unknown", compliance_score=100)
    except Exception:
        logging.exception("add_or_update_device failed (non-fatal)")

    # log the login in access_logs for audit (no risk_score)
    try:
        log_access(user_id=user["id"], username=username, resource="login", ip=client_ip,
                   device_type=device_type, user_agent=user_agent, risk_score=0, risk_level="INFO",
                   decision="LOGIN", details=f"device_matched={device_matched}")
    except Exception:
        logging.exception("log_access failed for successful login (non-fatal)")

    # Return token and device match flag (no risk_score)
    return jsonify({"access_token": token, "device_matched": device_matched, "expires_in_minutes": ACCESS_TOKEN_EXP_MINUTES}), 200


@app.route("/logout", methods=["POST"])
@token_required
def logout():
    # token_required validated the token and set g.session (if session exists)
    # We'll try to extract jti and revoke the session.
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return jsonify({"error": "Missing token"}), 401

    jti = get_jti_from_token(token)
    if not jti:
        return jsonify({"message": "logged out (no session id found)"}), 200

    try:
        rows = revoke_session_by_jti(jti)
        if rows:
            return jsonify({"message": "Logged out; session invalidated"}), 200
        else:
            return jsonify({"message": "Session not found or already revoked"}), 200
    except Exception:
        logging.exception("logout failed")
        return jsonify({"error": "internal"}), 500


# ---------------------------
# Protected resource (PEP)
# ---------------------------
@app.route("/resource/<resource_id>", methods=["GET", "POST"])
@token_required
def resource(resource_id):
    # token user
    token_username = g.user["username"]
    token_user_id = g.user["id"]
    user_role = g.user.get("role", "user")

    # Determine username requested: prefer query param ?username=..., else token user
    req_username = request.args.get("username")
    if req_username:
        username_for_request = req_username
    else:
        username_for_request = token_username

    # Map requested username to user_id if possible (this lets risk be computed for target user)
    target_user = get_user_by_username(username_for_request)
    target_user_id = target_user["id"] if target_user else None

    # Use client IP and user agent
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "unknown")
    device_type = request.headers.get("X-Device-Type") or None
    fingerprint = user_agent

    # Update device info (keep existing behavior)
    try:
        add_or_update_device(token_user_id, fingerprint, compliance_score=0)
    except Exception:
        logging.exception("add_or_update_device failed (non-fatal)")

    parsed_body = {}

    logging.info("=== Incoming Request START ===")
    logging.info("Endpoint: /resource/%s", resource_id)
    logging.info("Requested for username: %s (token user: %s)", username_for_request, token_username)
    logging.info("Client IP: %s", ip)
    logging.info("User-Agent: %s", user_agent)

    # Call risk engine (pass empty body_data). Use target_user_id if available.
    try:
        if compute_risk:
            risk_score, risk_level, details = compute_risk(
                user_id=target_user_id,
                ip=ip,
                user_agent=user_agent,
                body_data={}
            )
        else:
            risk_score, risk_level, details = 0, "INFO", "risk_engine_not_loaded"
    except Exception as e:
        logging.exception("Risk engine error")
        risk_score, risk_level, details = 100, "HIGH", f"risk_engine_error:{e}"

    opa_input = {
        "user": {"username": username_for_request, "role": user_role},
        "resource": {"id": resource_id},
        "ip": ip,
        "user_agent": user_agent,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "time": None,
        "body": {}
    }
    logging.info("OPA input: %s", opa_input)

    try:
        decision = query_opa(opa_input) if query_opa else None
    except Exception as e:
        logging.warning("OPA unavailable or error: %s - using fallback decision", e)
        decision = None

    if not decision:
        if risk_score < 30:
            decision = {"allow": True, "mode": "full", "reason": "fallback-low-risk"}
        elif risk_score < 60:
            decision = {"allow": True, "mode": "read-only", "reason": "fallback-medium-risk"}
        else:
            decision = {"allow": False, "mode": "deny", "reason": "fallback-high-risk"}

    mode = decision.get("mode", "deny")
    allowed = bool(decision.get("allow", False))
    reason = decision.get("reason", "")

    # Log to DB (keep details readable)
    try:
        log_access(
            user_id=token_user_id,
            username=username_for_request,
            resource=resource_id,
            ip=ip,
            device_type=device_type,
            user_agent=user_agent,
            risk_score=risk_score,
            risk_level=risk_level,
            decision=mode,
            details=(str(details) + "|" + reason + f"|actor={token_username}")
        )
    except Exception:
        logging.exception("log_access failed (non-fatal)")

    logging.info("Final decision -> allowed=%s mode=%s reason=%s risk_score=%s risk_level=%s",
                 allowed, mode, reason, risk_score, risk_level)
    logging.info("=== Incoming Request END ===")

    if not allowed:
        return jsonify({"error": "Access denied", "reason": reason,
                        "risk_score": risk_score, "risk_level": risk_level, "details": details}), 403

    if mode == "read-only":
        return jsonify({
            "resource": resource_id,
            "mode": "read-only",
            "data": f"READ-ONLY view of resource {resource_id}. (Limited fields)",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reason": reason,
            "details": details
        }), 200

    return jsonify({
        "resource": resource_id,
        "mode": "full",
        "data": f"FULL access granted to resource {resource_id}.",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": reason,
        "details": details
    }), 200


# ---------------------------
# Admin logs viewer
# ---------------------------
@app.route("/admin/logs", methods=["GET"])
@token_required
def view_logs():
    if g.user.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, username, resource, ip, user_agent, timestamp, risk_score, risk_level, decision, details FROM access_logs ORDER BY id DESC LIMIT 200")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"logs": rows}), 200
    except Exception as e:
        logging.exception("Failed to read logs")
        return jsonify({"error": "internal error", "details": str(e)}), 500


# ---------------------------
# other admin endpoints unchanged...
# ---------------------------

# Frontend pages
@app.route("/", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")

@app.route("/login_page", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/register_page", methods=["GET"])
def register_page():
    return render_template("register.html")


# App runner (keep last)
if __name__ == "__main__":
    # For debugging in development; in production use a WSGI server
    app.run(host="0.0.0.0", port=5000, debug=True)
