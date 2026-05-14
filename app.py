import os
import re
import io
import socket
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from base64 import urlsafe_b64encode

import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, g, flash
)

from bs4 import BeautifulSoup
import whois
import dns.resolver
import tldextract
from email import policy
from email.parser import BytesParser
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import dkim
from dotenv import load_dotenv

load_dotenv()

DB_PATH = "analysis.db"
HF_MODEL = os.getenv("HF_MODEL", "cybersectony/phishing-email-detection-distilbert_v2.4.1")
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
HF_API_KEY = os.getenv("HF_API_KEY")
HF_MODEL_ID = os.getenv("HF_MODEL", "cybersectony/phishing-email-detection-distilbert_v2.4.1")
HF_API_URL = f"https://router.huggingface.co/hf-inference/models/{HF_MODEL_ID}"

SUSPICIOUS_TLDS = {'.zip', '.country', '.top', '.work', '.review', '.link', '.xin', '.tk'}


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")


def hf_inference(text):
    """
    Calls Hugging Face Inference API and returns ALL predictions.
    Handles single-label and multi-label outputs.
    Maps raw label names to meaningful names.
    Returns: a list of {"label": str, "score": float} for all labels, 
             and the single best prediction {"label": str, "score": float}.
    """
    label_mapping = {
        "LABEL_0": "legitimate_email",
        "LABEL_1": "phishing_url",
        "LABEL_2": "legitimate_url",
        "LABEL_3": "phishing_url_alt"
    }
    
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {
        "inputs": text, 
        "options": {"wait_for_model": True},
        "parameters": {"return_all_scores": True}
    }
    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        output = response.json()

        all_scores = []
        best_prediction = {"label": "ERROR", "score": 0.0}

        predictions = []
        if isinstance(output, list) and output:
            if isinstance(output[0], list):
                predictions = output[0]
            else:
                predictions = output

        for pred in predictions:
            raw_label = pred.get("label", "ERROR")
            mapped_label = label_mapping.get(raw_label, raw_label)
            score = float(pred.get("score", 0)) * 100
            
            all_scores.append({
                "raw_label": raw_label,
                "label": mapped_label, 
                "score": score
            })
            
            if score > best_prediction["score"]:
                best_prediction = {"label": mapped_label, "score": score}

        present_labels = {s['label'] for s in all_scores}
        for raw, mapped in label_mapping.items():
            if mapped not in present_labels:
                all_scores.append({
                    "raw_label": raw,
                    "label": mapped, 
                    "score": 0.0
                })

        all_scores.sort(key=lambda x: x['label'])

        return {"all_scores": all_scores, "best_prediction": best_prediction}
    
    except Exception as e:
        print("HF API call failed:", e)
        return {"all_scores": [], "best_prediction": {"label": "ERROR", "score": 0.0}}


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            subject TEXT,
            sender TEXT,
            verdict TEXT,
            score REAL,
            summary TEXT,
            raw_text TEXT
        )
    """)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

URL_REGEX = re.compile(r'https?://[^\s\'\"<>]+', re.IGNORECASE)

def parse_eml(file_stream):
    """Parse .eml binary stream and return headers, plain text body and raw bytes."""
    try:
        raw_bytes = file_stream.read()
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as e:
        return {"error": f"Failed to parse .eml: {e}"}
    headers = {}
    for k in ["From", "To", "Subject", "Date", "Message-ID", "Authentication-Results", "Received-SPF", "DKIM-Signature"]:
        headers[k] = msg[k] or ""
    
    plain = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    plain += part.get_content()
                except Exception:
                    pass
    else:
        try:
            plain = msg.get_content()
        except Exception:
            plain = ""
    if not plain:
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    html = part.get_content()
                    plain = BeautifulSoup(html, "html.parser").get_text("\n")
                    break
                except Exception:
                    pass
    return {"headers": headers, "body": plain or "", "raw_bytes": raw_bytes}

def extract_urls(text):
    urls = re.findall(URL_REGEX, text or "")
    cleaned = []
    for u in urls:
        u = u.rstrip(".,;:)")
        cleaned.append(u)
    soup = BeautifulSoup(text or "", "html.parser")
    for a in soup.find_all("a", href=True):
        if a["href"] not in cleaned:
            cleaned.append(a["href"])
    return cleaned

def domain_from_url(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.lower()
    except Exception:
        return ""

def is_ip_address(host):
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False

def domain_age_days(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if isinstance(created, str):
                created = datetime.fromisoformat(created)
            age = (datetime.utcnow() - created).days
            return age
    except Exception:
        pass
    return None

def dns_resolve(domain):
    info = {"resolves": False, "ips": []}
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        for r in answers:
            info["ips"].append(r.to_text())
        info["resolves"] = bool(info["ips"])
    except Exception:
        pass
    return info

def tld_suspicious(domain):
    ext = tldextract.extract(domain)
    if not ext.suffix:
        return False
    return f".{ext.suffix.lower()}" in SUSPICIOUS_TLDS

def vt_headers():
    if not VT_API_KEY:
        return None
    return {"x-apikey": VT_API_KEY}

def vt_domain_report(domain):
    """
    Query VirusTotal domain endpoint:
    GET /domains/{domain}
    Returns parsed JSON or None on failure/no-key.
    """
    if not VT_API_KEY:
        return None
    url = f"{VT_BASE}/domains/{domain}"
    try:
        r = requests.get(url, headers=vt_headers(), timeout=8)
        if r.status_code == 200:
            return r.json()
        return {"error": f"VT responded {r.status_code}", "status_code": r.status_code}
    except Exception as e:
        return {"error": str(e)}

def vt_url_report(url):
    """
    For URLs, v3 requires we first POST to /urls with 'url' form data,
    then GET /urls/{id} where id is base64url encode of the URL.
    We'll try POST then GET to fetch last_analysis_stats (if key present).
    """
    if not VT_API_KEY:
        return None
    try:
        post = requests.post(f"{VT_BASE}/urls", data={"url": url}, headers=vt_headers(), timeout=8)
        if post.status_code not in (200, 201):
            return {"error": f"VT POST /urls {post.status_code}"}
        dataid = post.json().get("data", {}).get("id")
        if not dataid:
            urlid = urlsafe_b64encode(url.encode()).decode().strip("=")
            geturl = f"{VT_BASE}/urls/{urlid}"
        else:
            geturl = f"{VT_BASE}/urls/{dataid}"
        r = requests.get(geturl, headers=vt_headers(), timeout=8)
        if r.status_code == 200:
            return r.json()
        return {"error": f"VT GET {geturl} -> {r.status_code}", "status_code": r.status_code}
    except Exception as e:
        return {"error": str(e)}

def score_url(url, display_text=None):
    host = domain_from_url(url)
    checks = []
    score = 0

    if not host:
        checks.append(("no_host", "URL parsing failed"))
        score += 3
        return {"url": url, "host": host, "score": score, "checks": checks}

    if is_ip_address(host):
        checks.append(("ip_in_url", "URL uses raw IP address"))
        score += 3

    if len(url) > 100:
        checks.append(("long_url", f"very long URL ({len(url)} chars)"))
        score += 1

    if tld_suspicious(host):
        checks.append(("suspicious_tld", "Top-level domain flagged"))
        score += 2

    age = domain_age_days(host)
    if age is not None:
        if age < 60:
            checks.append(("young_domain", f"Domain age {age} days"))
            score += 3
        elif age < 365:
            checks.append(("new_domain", f"Domain age {age} days"))
            score += 1
    else:
        checks.append(("no_whois", "WHOIS lookup failed/blocked"))
        score += 1

    res = dns_resolve(host)
    if not res["resolves"]:
        checks.append(("no_dns", "Domain did not resolve"))
        score += 3
    else:
        for ip in res["ips"]:
            if ip.startswith(("10.", "192.168.", "172.")):
                checks.append(("private_ip", f"Resolves to private IP {ip}"))
                score += 2

    vt_dom = vt_domain_report(host)
    vt_summary = None
    if vt_dom:
        vt_summary = vt_dom
        try:
            stats = vt_dom.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if mal > 0 or suspicious > 0:
                checks.append(("vt_domain_report", f"VT detected {mal} malicious, {suspicious} suspicious engines"))
                score += 4
        except Exception:
            pass

    vt_url = vt_url_report(url)
    vt_url_summary = None
    if vt_url and isinstance(vt_url, dict) and "error" not in vt_url:
        vt_url_summary = vt_url
        try:
            stats = vt_url.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if mal > 0 or suspicious > 0:
                checks.append(("vt_url_report", f"VT detected {mal} malicious, {suspicious} suspicious engines"))
                score += 5
        except Exception:
            pass

    return {
        "url": url,
        "host": host,
        "score": score,
        "checks": checks,
        "whois_age_days": age,
        "dns": res,
        "vt_domain": vt_summary,
        "vt_url": vt_url_summary
    }

def check_spf_from_headers(headers):
    """
    Look for Authentication-Results or Received-SPF or Received headers to determine SPF result heuristically.
    Also fetch SPF TXT record for domain if possible.
    """
    results = {"spf_header": None, "spf_txt_exists": False, "sender_domain": None}

    auth = headers.get("Authentication-Results","") or headers.get("Auth-Results","")
    rcv_spf = headers.get("Received-SPF","")
    if auth:
        results["spf_header"] = auth
    if rcv_spf:
        results["spf_header"] = rcv_spf

    sender = headers.get("From","")
    m = re.search(r"@([A-Za-z0-9.\-]+)", sender)
    if m:
        domain = m.group(1).lower()
        results["sender_domain"] = domain
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=4)
            for r in answers:
                text = "".join(r.strings) if hasattr(r, "strings") else str(r)
                if "v=spf1" in text.lower():
                    results["spf_txt_exists"] = True
                    break
        except Exception:
            pass

    return results

def check_dkim(raw_eml_bytes):
    """
    Use dkimpy to verify DKIM signature if raw bytes available.
    Returns dict with keys: verified (bool), reason (str), selector (maybe)
    """
    out = {"dkim_present": False, "verified": None, "reason": None}
    if not raw_eml_bytes:
        return out
    if b"dkim-signature:" not in raw_eml_bytes.lower():
        return out
    out["dkim_present"] = True
    try:
        verified = dkim.verify(raw_eml_bytes)
        out["verified"] = bool(verified)
    except Exception as e:
        out["verified"] = False
        out["reason"] = str(e)
    return out

def build_forensic_report(parsed):
    parts = []
    total_heuristic_score = 0
    link_scores = sum(ui.get('score', 0) for ui in parsed.get("urls_info", []))
    total_heuristic_score += link_scores
    
    hf_result = parsed.get("hf_best", {})
    hf_best = hf_result.get("best_prediction", {})
    all_hf_scores = hf_result.get("all_scores", [])
    
    parts.append("=" * 60)
    parts.append("MACHINE LEARNING MODEL ANALYSIS")
    parts.append("=" * 60)
    
    ml_label = hf_best.get("label", "Unknown").lower()
    ml_confidence = hf_best.get('score', 0)
    
    parts.append(f"Primary Classification: **{ml_label.upper().replace('_', ' ')}**")
    parts.append(f"Confidence: {ml_confidence:.2f}%")
    
    ml_risk_contribution = 0
    if "phishing" in ml_label:
        ml_risk_contribution = (ml_confidence / 100.0) * 4.0 
        parts.append(f"\n🧠 ML Risk Contribution: +{ml_risk_contribution:.2f} (High confidence in phishing label)")
    else:
        legit_conf = ml_confidence if ml_label.startswith("legitimate") else 0
        ml_risk_contribution = -(legit_conf / 100.0) * 2.0 
        parts.append(f"\n🧠 ML Risk Contribution: {ml_risk_contribution:.2f} (Confidence in legitimate label)")
        
    parts.append("")

    body_text = parsed.get("body", "").lower()
    suspicious_phrases = [
        "urgent action", "immediately", "suspend your account", "verify your identity", 
        "wire transfer", "gift card", "bitcoin", "unauthorized access", "click here", 
        "account limited", "security alert", "confirm your password"
    ]
    
    found_keywords = [phrase for phrase in suspicious_phrases if phrase in body_text]
    keyword_score = 0
    
    if found_keywords:
        parts.append("=" * 60)
        parts.append("CONTENT & SEMANTIC ANALYSIS")
        parts.append("=" * 60)
        parts.append(f"⚠️ Suspicious Keywords Detected: {len(found_keywords)}")
        parts.append(f"Keywords: {', '.join(found_keywords)}")
        
        keyword_score = min(len(found_keywords) * 1.5, 6.0)
        parts.append(f"Content Risk Contribution: +{keyword_score:.2f}")
        total_heuristic_score += keyword_score
        parts.append("")

    hdr = parsed.get("headers", {})
    sender = hdr.get("From","")
    parts.append("=" * 60)
    parts.append("EMAIL HEADER ANALYSIS")
    parts.append("=" * 60)
    parts.append(f"Sender: {sender}")
    
    addr_mismatch_score = 0
    if "<" in sender and ">" in sender:
        try:
            display = sender.split("<")[0].strip().strip('"')
            addr = sender.split("<")[1].split(">")[0].strip()
            if display and addr and display.lower() not in addr.lower() and display != addr:
                parts.append("🚩 WARNING: Display name and email address mismatch detected")
                addr_mismatch_score += 1.5
        except Exception:
            pass
    parts.append(f"Header Risk Contribution: +{addr_mismatch_score}")
    total_heuristic_score += addr_mismatch_score
    parts.append("")

    parts.append("=" * 60)
    parts.append("EMAIL AUTHENTICATION ANALYSIS")
    parts.append("=" * 60)
    
    auth_risk_score = 0
    spf = parsed.get("spf", {})
    spf_status = spf.get("spf_header") or ""
    
    if "pass" in spf_status.lower():
        parts.append("SPF Status: ✅ PASS")
    elif "fail" in spf_status.lower() or "softfail" in spf_status.lower():
        parts.append("SPF Status: ❌ FAIL/SOFTFAIL")
        auth_risk_score += 2.5
    else:
        parts.append("SPF Status: ❓ NEUTRAL/NONE")
        auth_risk_score += 1
    
    dkim = parsed.get("dkim", {})
    if dkim.get("dkim_present"):
        if dkim.get("verified") is True:
            parts.append("DKIM: ✅ VERIFIED")
        else:
            parts.append("DKIM: ❌ FAILED")
            auth_risk_score += 3
    else:
        parts.append("DKIM: ❓ NOT PRESENT")
        auth_risk_score += 1

    parts.append(f"Authentication Risk Contribution: +{auth_risk_score}")
    total_heuristic_score += auth_risk_score
    parts.append("")

    urls_info = parsed.get("urls_info", [])
    if urls_info:
        parts.append("=" * 60)
        parts.append(f"LINK ANALYSIS ({len(urls_info)} links found)")
        parts.append("=" * 60)
        for idx, ui in enumerate(urls_info, 1):
            parts.append(f"Link #{idx}: {ui['host']} (Risk: {ui['score']})")
    else:
        parts.append("=" * 60)
        parts.append("LINK ANALYSIS")
        parts.append("=" * 60)
        parts.append("No URLs found in email content.")
    parts.append("")

    final_score = total_heuristic_score + ml_risk_contribution
    
    verdict = "LEGITIMATE"
    if final_score >= 7.5: 
        verdict = "PHISHING"
    elif final_score >= 4.5:
        verdict = "SUSPICIOUS"

    parts.append("=" * 60)
    parts.append("FINAL ASSESSMENT")
    parts.append("=" * 60)
    parts.append(f"Heuristic Score: {total_heuristic_score}")
    parts.append(f"ML Adjustment: {ml_risk_contribution:.2f}")
    parts.append(f"FINAL RISK SCORE: {final_score:.2f}")
    parts.append(f"VERDICT: {verdict}")

    return "\n".join(parts), final_score, verdict

def generate_pdf_report(analysis_record):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    x_margin = 50
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(x_margin, y, "Phishing Analysis Report")
    y -= 30
    c.setFont("Helvetica", 10)
    c.drawString(x_margin, y, f"Generated: {datetime.utcnow().isoformat()} UTC")
    y -= 20

    def draw_line(k, v):
        nonlocal y
        c.setFont("Helvetica-Bold", 11)
        c.drawString(x_margin, y, f"{k}:")
        c.setFont("Helvetica", 10)
        c.drawString(x_margin + 100, y, str(v))
        y -= 18

    draw_line("Subject", analysis_record.get("subject",""))
    draw_line("From", analysis_record.get("sender",""))
    draw_line("Verdict", analysis_record.get("verdict",""))
    draw_line("Score", f"{analysis_record.get('score',0):.2f}") 

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x_margin, y, "Forensic Summary:")
    y -= 16
    c.setFont("Helvetica", 9)
    text = c.beginText(x_margin, y)
    text.setLeading(12)
    summary = analysis_record.get("summary","")
    for line in summary.splitlines():
        while len(line) > 110:
            text.textLine(line[:110])
            line = line[110:]
        text.textLine(line)
    c.drawText(text)

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        eml_file = request.files.get("eml_file")
        pasted = request.form.get("email_text","").strip()
        raw_text = ""
        headers = {}
        raw_bytes = None

        if eml_file and eml_file.filename:
            parsed = parse_eml(eml_file.stream)
            if parsed.get("error"):
                flash(parsed["error"], "danger")
                return redirect(url_for("index"))
            raw_text = parsed.get("body","")
            headers = parsed.get("headers", {})
            raw_bytes = parsed.get("raw_bytes", None)
        else:
            raw_text = pasted
            raw_bytes = None
            headers = {}
            for k in ["From", "To", "Subject", "Date", "Authentication-Results", "Received-SPF", "DKIM-Signature"]:
                m = re.search(rf"^{k}:\s*(.+)$", pasted, flags=re.MULTILINE | re.IGNORECASE)
                headers[k] = m.group(1).strip() if m else ""

        if not raw_text:
            flash("No email body detected. Paste text or upload a .eml file.", "warning")
            return redirect(url_for("index"))

        urls = extract_urls(raw_text)
        urls_info = []
        max_link_score = 0
        for u in urls:
            ui = score_url(u)
            urls_info.append(ui)
            if ui['score'] > max_link_score:
                max_link_score = ui['score']

        try:
            hf_result = hf_inference(raw_text) 
        except Exception as e:
            hf_result = {"all_scores":[], "best_prediction":{"label":"ERROR","score":0}}
            flash(f"HuggingFace inference failed: {e}", "danger")

        best_label = hf_result['best_prediction']['label']
        best_score = hf_result['best_prediction']['score']
        
        override_label = None

        if not urls and best_label in ['phishing_url', 'phishing_url_alt']:
            override_label = "legitimate_email"

        elif urls and best_label in ['phishing_url', 'phishing_url_alt'] and max_link_score < 3:
            override_label = "legitimate_url"

        if override_label:
            new_all_scores = []
            for item in hf_result['all_scores']:
                if item['label'] == best_label:
                    item['score'] = 0.01  
                elif item['label'] == override_label:
                    item['score'] = best_score 
                new_all_scores.append(item)
            
            new_all_scores.sort(key=lambda x: x['label'])
            hf_result['all_scores'] = new_all_scores
            hf_result['best_prediction'] = {
                "label": override_label,
                "score": best_score
            }

        spf = check_spf_from_headers(headers)
        dkim_res = check_dkim(raw_bytes)

        parsed_pack = {"headers": headers, "body": raw_text, "hf_best": hf_result, "urls_info": urls_info, "spf": spf, "dkim": dkim_res}

        summary_text, final_score, verdict = build_forensic_report(parsed_pack)
        
        now = datetime.utcnow().isoformat()
        db = get_db()
        db.execute(
            "INSERT INTO analyses (timestamp, subject, sender, verdict, score, summary, raw_text) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now, headers.get("Subject",""), headers.get("From",""), verdict, final_score, summary_text, raw_text)
        )
        db.commit()
        record_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        return render_template(
            "result.html",
            hf_result=hf_result, 
            urls_info=urls_info,
            headers=headers,
            body=raw_text,
            summary=summary_text,
            verdict=verdict,
            score=final_score,
            record_id=record_id,
            spf=spf,
            dkim=dkim_res
        )

    return render_template("index.html")

@app.route("/history")
def history():
    db = get_db()
    rows = db.execute("""
        SELECT * FROM analyses
        ORDER BY timestamp DESC
        LIMIT 200
    """).fetchall()
    return render_template("history.html", rows=rows)

@app.route("/report/<int:record_id>/pdf")
def download_pdf(record_id):
    db = get_db()
    row = db.execute("SELECT * FROM analyses WHERE id = ?", (record_id,)).fetchone()
    if not row:
        flash("Record not found.", "danger")
        return redirect(url_for("history"))
    rec = dict(row)
    pdf_io = generate_pdf_report(rec)
    return send_file(pdf_io, mimetype="application/pdf", as_attachment=True, download_name=f"phish_report_{record_id}.pdf")


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)