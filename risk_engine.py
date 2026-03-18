# risk_engine.py
import datetime
import logging
from db import get_devices_for_user, get_recent_access_count

IP_WHITELIST = ["127.0.0.1", "::1"]
IP_BLACKLIST = ["123.123.123.123"]

def _use_precomputed(body):
    """
    Detect whether client supplied pre-computed factor fields.
    We'll accept either a numeric 'risk_pct' or any of the f_* keys.
    """
    if not isinstance(body, dict):
        return False
    if "risk_pct" in body:
        return True
    for k in ("f_device", "f_failed", "f_access", "f_geo", "f_simulate"):
        if k in body:
            return True
    return False

def _clamp01(x):
    try:
        x = float(x)
    except Exception:
        return 0.0
    if x < 0: return 0.0
    if x > 1: return 1.0
    return x

def _call_get_recent_access_count(user_id, minutes=60, only_failed=False):
    """
    Safe wrapper: try to call get_recent_access_count with optional kwargs if the function supports them.
    Fallback to calling with just user_id.
    """
    try:
        # try with kwargs
        return get_recent_access_count(user_id, minutes=minutes, only_failed=only_failed)
    except TypeError:
        try:
            # try with (user_id, minutes)
            return get_recent_access_count(user_id, minutes)
        except TypeError:
            try:
                return get_recent_access_count(user_id)
            except Exception:
                return 0
    except Exception:
        return 0

def _call_get_devices_for_user(user_id):
    try:
        return get_devices_for_user(user_id) or []
    except Exception:
        return []

def compute_risk(user_id, ip, user_agent, body_data=None):
    """
    Compute a normalized risk score (0-100) and risk level.
    Behavior:
      * If body_data contains explicit precomputed factors (risk_pct or f_*), use them (dev/test mode).
      * Else if body_data contains explicit 'simulate' or simulate fields, use them (dev/test).
      * Otherwise, compute features server-side using DB + request metadata.
    Returns: (risk_score_numeric, risk_level_str, details_dict)
    """
    details = {}
    body = body_data or {}

    # 1) Precomputed fields (explicit risk_pct or f_*) -> use directly
    if body and _use_precomputed(body):
        # Prefer explicit risk_pct if present
        if "risk_pct" in body:
            try:
                pct = float(body.get("risk_pct", 0.0))
            except Exception:
                pct = 0.0
            details.update(body if isinstance(body, dict) else {})
            pct = max(0.0, min(100.0, pct))
            if pct <= 30:
                level = "LOW"
            elif pct <= 60:
                level = "MEDIUM"
            else:
                level = "HIGH"
            details["source"] = "precomputed"
            details["risk_pct"] = round(pct, 2)
            return round(pct, 2), level, details

        # Otherwise try to use individual f_* fields (0..1)
        f_device = _clamp01(body.get("f_device", 0))
        f_failed = _clamp01(body.get("f_failed", 0))
        f_access = _clamp01(body.get("f_access", 0))
        f_geo    = _clamp01(body.get("f_geo", 0))
        f_sim    = _clamp01(body.get("f_simulate", body.get("f_sim", 0)))
        pct = (f_device * 20) + (f_failed * 20) + (f_access * 20) + (f_geo * 20) + (f_sim * 20)
        details.update({
            "f_device": f_device,
            "f_failed": f_failed,
            "f_access": f_access,
            "f_geo": f_geo,
            "f_simulate": f_sim,
            "source": "precomputed_parts"
        })
        details["risk_pct"] = round(pct, 2)
        if pct <= 30:
            level = "LOW"
        elif pct <= 60:
            level = "MEDIUM"
        else:
            level = "HIGH"
        return round(pct, 2), level, details

    # 2) If body explicitly contains simulation fields (simulate / simulate_*), use simulate path
    simulate_present = bool(body and (("simulate" in body) or ("simulate_access_count" in body) or ("simulate_failed_count" in body) or ("simulate_device_compliance" in body)))
    if simulate_present:
        # Same simulate logic previously used
        simulate = body.get("simulate", "none")
        device_status = body.get("device_status", "trusted")
        suspicious_ip = body.get("suspicious_ip", None)
        try:
            simulate_access_count = float(body.get("simulate_access_count", body.get("access_count", 1)))
        except Exception:
            simulate_access_count = 1.0
        try:
            simulate_failed_count = float(body.get("simulate_failed_count", body.get("failed_count", 0)))
        except Exception:
            simulate_failed_count = 0.0
        try:
            simulate_device_compliance = float(body.get("simulate_device_compliance", body.get("device_compliance", 95)))
        except Exception:
            simulate_device_compliance = 95.0

        f_device = 1.0 - (simulate_device_compliance / 100.0)
        details["device_compliance"] = simulate_device_compliance
        details["f_device"] = round(_clamp01(f_device), 4)

        f_failed = min(simulate_failed_count / 10.0, 1.0)
        details["simulate_failed_count"] = simulate_failed_count
        details["f_failed"] = round(_clamp01(f_failed), 4)

        f_access = min(simulate_access_count / 10.0, 1.0)
        details["simulate_access_count"] = simulate_access_count
        details["f_access"] = round(_clamp01(f_access), 4)

        f_geo = 1.0 if (suspicious_ip and suspicious_ip in IP_BLACKLIST) else 0.0
        if not suspicious_ip:
            if ip and ip not in IP_WHITELIST:
                f_geo = 0.0
        details["suspicious_ip"] = suspicious_ip
        details["f_geo"] = round(_clamp01(f_geo), 4)

        if str(simulate).lower() == "high":
            f_sim = 1.0
        elif str(simulate).lower() == "medium":
            f_sim = 0.5
        else:
            f_sim = 0.0
        details["simulate"] = simulate
        details["f_simulate"] = round(_clamp01(f_sim), 4)

        pct = (details["f_device"] * 20.0) + (details["f_failed"] * 20.0) + (details["f_access"] * 20.0) + (details["f_geo"] * 20.0) + (details["f_simulate"] * 20.0)
        pct = max(0.0, min(100.0, round(pct, 2)))
        details["risk_pct"] = pct
        if pct <= 30:
            level = "LOW"
        elif pct <= 60:
            level = "MEDIUM"
        else:
            level = "HIGH"
        details["computed_by"] = "simulate-path"
        return pct, level, details

            # 3) SERVER-SIDE DERIVED PATH: compute dynamically based on DB + metadata
    details["computed_by"] = "server-derived"

    # -----------------------------
    # 1️⃣ DEVICE COMPLIANCE FACTOR
    # -----------------------------
    try:
        devices = get_devices_for_user(user_id)
        if devices:
            comp_scores = []
            for d in devices:
                if isinstance(d, dict):
                    comp_scores.append(float(d.get("compliance_score", 100)))
                elif isinstance(d, (list, tuple)):
                    for item in d:
                        try:
                            val = float(item)
                            if 0 <= val <= 100:
                                comp_scores.append(val)
                                break
                        except Exception:
                            continue
            avg_comp = sum(comp_scores) / len(comp_scores) if comp_scores else 100.0
        else:
            avg_comp = 100.0
    except Exception as e:
        logging.warning("Device fetch failed: %s", e)
        avg_comp = 100.0

    # Lower compliance = higher device risk
    if avg_comp < 50:
        f_device = 1.0
    elif avg_comp < 80:
        f_device = 0.5
    else:
        f_device = 0.1
    details["avg_device_compliance"] = round(avg_comp, 2)
    details["f_device"] = f_device

    # -----------------------------
    # 2️⃣ RECENT ACCESS FREQUENCY FACTOR
    # -----------------------------
    try:
        recent_access = get_recent_access_count(user_id, minutes=5)
    except Exception as e:
        logging.warning("get_recent_access_count failed: %s", e)
        recent_access = 0

    if recent_access > 10:
        f_access = 1.0
    elif recent_access > 5:
        f_access = 0.6
    else:
        f_access = 0.1
    details["recent_access_count_5min"] = recent_access
    details["f_access"] = f_access

    # -----------------------------
    # 3️⃣ FAILED LOGIN ATTEMPTS FACTOR
    # -----------------------------
    try:
        recent_failed = get_recent_access_count(user_id, minutes=10, only_failed=True)
    except Exception as e:
        logging.warning("get_recent_access_count(only_failed) failed: %s", e)
        recent_failed = 0

    if recent_failed >= 5:
        f_failed = 1.0
    elif recent_failed >= 3:
        f_failed = 0.6
    else:
        f_failed = 0.0
    details["recent_failed_count_10min"] = recent_failed
    details["f_failed"] = f_failed

    # -----------------------------
    # 4️⃣ GEO / IP RISK FACTOR
    # -----------------------------
    if ip in IP_BLACKLIST:
        f_geo = 1.0
    elif ip not in IP_WHITELIST:
        f_geo = 0.3  # unknown IP = slightly risky
    else:
        f_geo = 0.0
    details["ip"] = ip
    details["f_geo"] = f_geo

    # -----------------------------
    # 🔢 FINAL RISK SCORE (weights)
    # -----------------------------
    # weight the factors — feel free to tune numbers later
    pct = (
        f_device * 25 +
        f_access * 25 +
        f_failed * 25 +
        f_geo * 25
    )

    pct = max(0.0, min(100.0, round(pct, 2)))
    details["risk_pct"] = pct

    # -----------------------------
    # 🎯 DETERMINE RISK LEVEL
    # -----------------------------
    if pct <= 30:
        level = "LOW"
    elif pct <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return pct, level, details
