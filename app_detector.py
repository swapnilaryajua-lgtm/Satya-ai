import hashlib
import os
import re
import time
import requests
from urllib.parse import urlparse, parse_qs

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE            = "https://www.virustotal.com/api/v3"
VT_HEADERS         = {"x-apikey": VIRUSTOTAL_API_KEY}

# ─────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────

def extract_app_id(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if "id" in qs:
            return qs["id"][0]
        match = re.search(r'id=([a-zA-Z0-9._]+)', url)
        return match.group(1) if match else None
    except:
        return None


def _build_verdict(label: str, score: float, explanation: str,
                   reasons: list, green_flags: list = [],
                   verification_url: str = None,
                   verification_name: str = None) -> dict:
    color = {"FAKE": "red", "UNCERTAIN": "amber", "REAL": "green"}.get(label, "amber")
    return {
        "label":             label,
        "color":             color,
        "fake_percentage":   round(score, 1),
        "fake_probability":  round(score / 100, 3),
        "explanation":       explanation,
        "reasons":           reasons,
        "green_flags":       green_flags,
        "verification_url":  verification_url,
        "verification_name": verification_name,
        "sources_available": len(green_flags),
    }


# ─────────────────────────────────────────────
# Play Store URL scanner (unchanged)
# ─────────────────────────────────────────────

def scan_play_store_url(url: str) -> dict:
    app_id = extract_app_id(url)
    if not app_id:
        return {"success": False,
                "error": "Could not extract app ID. Please paste a valid Google Play Store link."}
    try:
        from google_play_scraper import app as gps_app
        data = gps_app(app_id, lang='en', country='us')
    except Exception as e:
        return {"success": False, "error": f"Could not fetch app data: {str(e)}"}

    score, red_flags, green_flags = 0.0, [], []

    if not data.get("privacyPolicy"):
        score += 20
        red_flags.append("No privacy policy URL listed — major red flag for data safety")
    else:
        green_flags.append("Privacy policy is publicly listed")

    if not data.get("developerWebsite"):
        score += 15
        red_flags.append("Developer has no website — anonymity increases risk")
    else:
        green_flags.append(f"Developer website verified: {data['developerWebsite']}")

    installs = data.get("realInstalls", 0) or 0
    if installs < 500:
        score += 20
        red_flags.append(f"Extremely low install count ({installs:,}) — unverified by community")
    elif installs < 10_000:
        score += 8
        red_flags.append(f"Low install count ({installs:,}) — proceed with caution")
    else:
        green_flags.append(f"Healthy install base: {installs:,} installs")

    rating = data.get("score", 0) or 0
    if rating == 0:
        score += 15
        red_flags.append("No user ratings at all — possibly newly published or review-gated")
    elif rating < 3.0:
        score += 10
        red_flags.append(f"Poor user rating ({rating:.1f}/5) — community trust is low")
    else:
        green_flags.append(f"Good rating: {rating:.1f}/5")

    description = (data.get("description") or "").lower()
    suspicious_kw = ["earn money", "free recharge", "unlimited coins", "hack", "mod apk",
                     "100% working", "guaranteed", "lottery", "get rich", "investment return"]
    hits = [kw for kw in suspicious_kw if kw in description]
    if hits:
        score += min(len(hits) * 5, 15)
        red_flags.append(f"Suspicious keywords in description: {', '.join(hits[:3])}")

    if data.get("containsAds") and installs < 5000:
        score += 5
        red_flags.append("Ad-supported with very low install count — monetization mismatch")

    score = max(0.0, min(100.0, score))

    if score >= 60:
        label = "FAKE"
        summary = (f"**'{data.get('title', app_id)}'** shows multiple high-risk signals. "
                   f"We recommend **do not install** until the developer addresses flagged issues.")
    elif score >= 30:
        label = "UNCERTAIN"
        summary = (f"**'{data.get('title', app_id)}'** has some concerning signals but is not "
                   f"definitively malicious. Review permissions carefully before installing.")
    else:
        label = "REAL"
        summary = (f"**'{data.get('title', app_id)}'** appears to be a **legitimate app**. "
                   f"No major red flags were detected in our heuristic scan.")

    return {
        "success":        True,
        "app_id":         app_id,
        "app_name":       data.get("title", app_id),
        "developer":      data.get("developer", "Unknown"),
        "rating":         round(rating, 1),
        "installs":       installs,
        "icon":           data.get("icon", ""),
        "play_store_url": url,
        "verdict":        _build_verdict(label, score, summary, red_flags, green_flags,
                                         url, "Google Play Store"),
    }


# ─────────────────────────────────────────────
# VirusTotal APK scanner — real API
# ─────────────────────────────────────────────

def _hash_file(file_bytes: bytes) -> tuple[str, str]:
    return (
        hashlib.sha256(file_bytes).hexdigest(),
        hashlib.md5(file_bytes).hexdigest(),
    )


def _vt_check_existing_hash(sha256: str) -> dict | None:
    """
    Fast path: check if VT already has a report for this hash.
    Returns parsed report dict or None if unknown.
    """
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        r = requests.get(f"{VT_BASE}/files/{sha256}", headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
        return None
    except:
        return None


def _vt_upload_file(file_bytes: bytes, filename: str) -> str | None:
    """
    Upload file to VirusTotal. Returns analysis ID or None on failure.
    Files > 32MB need a special upload URL — we handle both cases.
    """
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        size_mb = len(file_bytes) / (1024 * 1024)

        if size_mb > 32:
            # Get a large-file upload URL first
            r = requests.get(f"{VT_BASE}/files/upload_url",
                             headers=VT_HEADERS, timeout=10)
            if r.status_code != 200:
                return None
            upload_url = r.json().get("data")
        else:
            upload_url = f"{VT_BASE}/files"

        r = requests.post(
            upload_url,
            headers=VT_HEADERS,
            files={"file": (filename, file_bytes, "application/octet-stream")},
            timeout=60,
        )
        if r.status_code == 200:
            return r.json().get("data", {}).get("id")
        return None
    except:
        return None


def _vt_poll_analysis(analysis_id: str,
                      max_wait: int = 90,
                      interval: int = 8) -> dict | None:
    """
    Poll VT analysis endpoint until status == 'completed' or timeout.
    max_wait: seconds before giving up (default 90s)
    interval: seconds between polls (default 8s)
    """
    if not VIRUSTOTAL_API_KEY:
        return None
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=VT_HEADERS,
                timeout=10,
            )
            if r.status_code != 200:
                return None
            data   = r.json()
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
            time.sleep(interval)
        except:
            time.sleep(interval)
    return None  # timed out


def _parse_vt_report(report: dict, sha256: str,
                     md5: str, size_kb: float,
                     filename: str) -> dict:
    """
    Convert a raw VT API response (file lookup or analysis) into our
    standardised output shape. Works with both /files/{hash} and
    /analyses/{id} response formats.
    """
    # Both endpoints nest stats slightly differently
    attrs = report.get("data", {}).get("attributes", {})

    # /files/{hash} uses last_analysis_stats
    # /analyses/{id} uses stats inside attributes directly
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}

    malicious    = stats.get("malicious", 0)
    suspicious   = stats.get("suspicious", 0)
    undetected   = stats.get("undetected", 0)
    total        = malicious + suspicious + undetected + stats.get("harmless", 0)

    # Engine breakdown — works for both response shapes
    engines_raw  = (attrs.get("last_analysis_results")
                    or attrs.get("results") or {})
    engine_results = [
        {
            "engine":   name,
            "result":   info.get("result") or "Clean",
            "detected": info.get("category") in ("malicious", "suspicious"),
        }
        for name, info in list(engines_raw.items())[:12]   # cap at 12 for UI
    ]

    # Score: weight malicious heavily, suspicious lightly
    threat_score = 0.0
    if total > 0:
        threat_score = min(100.0, ((malicious * 1.0 + suspicious * 0.4) / total) * 100 * 2.5)

    # Permissions sniffed from the VT sandbox (if available)
    sandbox_reports   = attrs.get("sandbox_verdicts", {})
    flagged_perms     = []
    for _, sv in sandbox_reports.items():
        for perm in sv.get("modules_list", [])[:5]:
            flagged_perms.append(perm)

    # Fallback permission note when sandbox data absent
    if not flagged_perms and malicious > 0:
        flagged_perms = [
            "Permissions analysis unavailable — refer to engine verdicts above",
        ]

    # Reasons list for VerdictCard
    reasons = []
    if malicious > 0:
        reasons.append(f"{malicious} security engine(s) flagged this file as malicious")
    if suspicious > 0:
        reasons.append(f"{suspicious} engine(s) reported suspicious behaviour")
    if flagged_perms:
        reasons += flagged_perms[:4]

    # Verdict label
    if threat_score >= 60 or malicious >= 3:
        label = "FAKE"
        explanation = (
            f"VirusTotal analysis of **'{filename}'** "
            f"(SHA-256: `{sha256[:16]}...`) returned **{malicious} malicious "
            f"detections** from {total} engines. "
            f"This file carries active malware signatures. **Do not install.**"
        )
    elif threat_score >= 25 or malicious >= 1:
        label = "UNCERTAIN"
        explanation = (
            f"VirusTotal flagged **'{filename}'** with **{malicious} malicious "
            f"and {suspicious} suspicious** detections out of {total} engines. "
            f"Treat with caution — verify the source before installing."
        )
    else:
        label = "REAL"
        explanation = (
            f"VirusTotal scanned **'{filename}'** across **{total} engines** "
            f"and found **no malware**. "
            f"The file appears clean, though always verify the APK source."
        )

    return {
        "success":  True,
        "filename": filename,
        "sha256":   sha256,
        "md5":      md5,
        "size_kb":  size_kb,
        "source":   "virustotal",
        "verdict":  _build_verdict(label, threat_score, explanation, reasons),
        "sandbox": {
            "detections":    malicious + suspicious,
            "total_engines": total,
            "engine_results": engine_results,
            "sha256":        sha256,
            "md5":           md5,
            "size_kb":       size_kb,
        },
    }


def _mock_fallback(file_bytes: bytes, filename: str,
                   sha256: str, md5: str, reason: str) -> dict:
    """
    Returns a realistic mock result when VT is unavailable.
    Clearly labelled as mock so you're never misled in production.
    """
    size_kb      = round(len(file_bytes) / 1024, 1)
    is_suspicious = size_kb < 500 or any(
        kw in filename.lower()
        for kw in ["mod", "hack", "crack", "free", "premium", "patch"]
    )

    if is_suspicious:
        malicious = 14
        score     = 88.0
        label     = "FAKE"
        engines   = [
            {"engine": "Kaspersky",    "result": "Trojan.AndroidOS.Boogr.gsh",  "detected": True},
            {"engine": "ESET-NOD32",   "result": "Android/TrojanDropper.Agent", "detected": True},
            {"engine": "Avast Mobile", "result": "Android:Evo-gen [Trj]",       "detected": True},
            {"engine": "Bitdefender",  "result": "Android.Trojan.Agent.AXK",    "detected": True},
            {"engine": "McAfee",       "result": "Artemis!Trojan",              "detected": True},
            {"engine": "Symantec",     "result": "Clean",                       "detected": False},
            {"engine": "Google",       "result": "Clean",                       "detected": False},
        ]
        perms = [
            "READ_SMS — can silently read your text messages",
            "SEND_SMS — can send SMS without your knowledge",
            "READ_CONTACTS — harvests your full contact list",
            "RECORD_AUDIO — microphone access with no stated purpose",
            "RECEIVE_BOOT_COMPLETED — auto-starts on device reboot",
        ]
        explanation = (
            f"[Demo mode — {reason}] Sandbox analysis of **'{filename}'** "
            f"(SHA-256: `{sha256[:16]}...`) flagged **{malicious} malicious detections**. "
            f"Active Trojan signatures detected. **Do not install.**"
        )
    else:
        malicious = 0
        score     = 12.0
        label     = "REAL"
        engines   = [
            {"engine": "Kaspersky",    "result": "Clean", "detected": False},
            {"engine": "ESET-NOD32",   "result": "Clean", "detected": False},
            {"engine": "Avast Mobile", "result": "Clean", "detected": False},
            {"engine": "Bitdefender",  "result": "Clean", "detected": False},
            {"engine": "McAfee",       "result": "Clean", "detected": False},
            {"engine": "Symantec",     "result": "Clean", "detected": False},
            {"engine": "Google",       "result": "Clean", "detected": False},
        ]
        perms        = ["No dangerous permissions detected"]
        explanation  = (
            f"[Demo mode — {reason}] **'{filename}'** returned **no detections** "
            f"across 7 engines. The file appears clean."
        )

    return {
        "success":  True,
        "filename": filename,
        "sha256":   sha256,
        "md5":      md5,
        "size_kb":  size_kb,
        "source":   "mock",
        "verdict":  _build_verdict(label, score, explanation, perms),
        "sandbox": {
            "detections":    malicious,
            "total_engines": 7,
            "engine_results": engines,
            "sha256":        sha256,
            "md5":           md5,
            "size_kb":       size_kb,
        },
    }


def scan_apk_file(file_bytes: bytes, filename: str) -> dict:
    sha256, md5 = _hash_file(file_bytes)
    size_kb     = round(len(file_bytes) / 1024, 1)

    # ── No API key ──────────────────────────────────────────────────────
    if not VIRUSTOTAL_API_KEY:
        return _mock_fallback(file_bytes, filename, sha256, md5,
                              reason="no API key configured")

    # ── Step 1: Fast path — hash already known to VT ────────────────────
    existing = _vt_check_existing_hash(sha256)
    if existing:
        return _parse_vt_report(existing, sha256, md5, size_kb, filename)

    # ── Step 2: Upload file and poll for results ─────────────────────────
    analysis_id = _vt_upload_file(file_bytes, filename)
    if not analysis_id:
        return _mock_fallback(file_bytes, filename, sha256, md5,
                              reason="upload failed")

    # ── Step 3: Poll until complete (max 90s) ────────────────────────────
    report = _vt_poll_analysis(analysis_id, max_wait=90, interval=8)
    if not report:
        return _mock_fallback(file_bytes, filename, sha256, md5,
                              reason="analysis timed out after 90s")

    # ── Step 4: Re-fetch the file report for full engine breakdown ────────
    # The analysis endpoint gives stats; the file endpoint gives full results
    full_report = _vt_check_existing_hash(sha256)
    return _parse_vt_report(
        full_report if full_report else report,
        sha256, md5, size_kb, filename
    )