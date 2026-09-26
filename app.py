from flask import Flask, render_template, request, send_file
import socket
import ssl
import urllib.request
from urllib.parse import urlparse
import os
import requests
from io import BytesIO
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


app = Flask(__name__)


# -----------------------------
# Clean domain
# -----------------------------
def clean_domain(value):
    value = value.strip()

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)
    domain = parsed.netloc

    if ":" in domain:
        domain = domain.split(":")[0]

    return domain.lower()


# -----------------------------
# DNS Check
# -----------------------------
def check_dns(domain):
    try:
        ip = socket.gethostbyname(domain)

        return {
            "status": "Pass",
            "title": "DNS Resolution",
            "message": f"Domain resolves to {ip}."
        }

    except Exception as e:
        return {
            "status": "Fail",
            "title": "DNS Resolution",
            "message": "The domain could not be resolved."
        }


# -----------------------------
# HTTPS Check
# -----------------------------
def check_https(domain):
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=8,
            allow_redirects=True
        )

        return {
            "status": "Pass",
            "title": "HTTPS",
            "message": f"HTTPS is available (HTTP {response.status_code})."
        }

    except Exception:
        return {
            "status": "Fail",
            "title": "HTTPS",
            "message": "HTTPS connection could not be established."
        }


# -----------------------------
# TLS Certificate Check
# -----------------------------
def check_tls(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                if certificate:
                    return {
                        "status": "Pass",
                        "title": "TLS Certificate",
                        "message": "A TLS certificate was successfully obtained."
                    }

        return {
            "status": "Review",
            "title": "TLS Certificate",
            "message": "TLS certificate information could not be verified."
        }

    except Exception:
        return {
            "status": "Fail",
            "title": "TLS Certificate",
            "message": "A valid TLS connection could not be established."
        }


# -----------------------------
# Security Headers
# -----------------------------
def check_security_headers(domain):
    required_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options"
    ]

    try:
        response = requests.get(
            f"https://{domain}",
            timeout=8
        )

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        missing = [
            header
            for header in required_headers
            if header not in headers
        ]

        if not missing:
            return {
                "status": "Pass",
                "title": "Security Headers",
                "message": "Common security headers were detected."
            }

        return {
            "status": "Review",
            "title": "Security Headers",
            "message": (
                "Some common security headers were not detected: "
                + ", ".join(missing)
            )
        }

    except Exception:
        return {
            "status": "Review",
            "title": "Security Headers",
            "message": "Security headers could not be checked."
        }


# -----------------------------
# VirusTotal Check
# -----------------------------
def check_virustotal(domain):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "status": "Review",
            "title": "Threat Intelligence",
            "message": "VirusTotal API key is not configured."
        }, 0

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        response = requests.get(
            url,
            headers={
                "x-apikey": api_key
            },
            timeout=15
        )

        if response.status_code != 200:
            return {
                "status": "Review",
                "title": "Threat Intelligence",
                "message": "VirusTotal information could not be retrieved."
            }, 0

        data = response.json()

        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            status = "Fail"
        elif suspicious > 0:
            status = "Review"
        else:
            status = "Pass"

        message = (
            f"VirusTotal analysis: {malicious} malicious "
            f"and {suspicious} suspicious detections."
        )

        vt_risk = min(
            40,
            malicious * 8 + suspicious * 3
        )

        return {
            "status": status,
            "title": "Threat Intelligence",
            "message": message
        }, vt_risk

    except Exception:
        return {
            "status": "Review",
            "title": "Threat Intelligence",
            "message": "VirusTotal check could not be completed."
        }, 0


# -----------------------------
# Calculate Risk
# -----------------------------
def calculate_risk(findings, vt_risk):
    risk = 0

    for finding in findings:

        if finding["status"] == "Fail":
            risk += 20

        elif finding["status"] == "Review":
            risk += 8

    risk += vt_risk

    risk = min(risk, 100)

    if risk < 30:
        level = "Low"
    elif risk < 60:
        level = "Medium"
    else:
        level = "High"

    return risk, level


# -----------------------------
# Recommendations
# -----------------------------
def make_recommendation(findings):
    recommendations = []

    for finding in findings:

        if finding["title"] == "HTTPS" and finding["status"] != "Pass":
            recommendations.append(
                "Enable HTTPS and use a valid SSL/TLS certificate."
            )

        if finding["title"] == "TLS Certificate" and finding["status"] != "Pass":
            recommendations.append(
                "Install and maintain a valid TLS certificate."
            )

        if finding["title"] == "Security Headers" and finding["status"] != "Pass":
            recommendations.append(
                "Configure recommended HTTP security headers."
            )

        if finding["title"] == "Threat Intelligence" and finding["status"] != "Pass":
            recommendations.append(
                "Investigate threat-intelligence findings and monitor the domain."
            )

        if finding["title"] == "DNS Resolution" and finding["status"] != "Pass":
            recommendations.append(
                "Verify the domain's DNS configuration."
            )

    if not recommendations:
        recommendations.append(
            "Continue monitoring the domain and regularly review security settings."
        )

    return recommendations


# -----------------------------
# PDF Report
# -----------------------------
def build_pdf(domain, risk_score, risk_level, findings, recommendations):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph("Company Risk Watch", styles["Title"])
    )

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            f"<b>Domain:</b> {domain}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {risk_score}%",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Level:</b> {risk_level}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph("Security Findings", styles["Heading2"])
    )

    for finding in findings:

        story.append(
            Paragraph(
                f"<b>{finding['status']} — {finding['title']}</b>",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                finding["message"],
                styles["Normal"]
            )
        )

        story.append(Spacer(1, 10))

    story.append(
        Paragraph("Recommendations", styles["Heading2"])
    )

    for recommendation in recommendations:

        story.append(
            Paragraph(
                "• " + recommendation,
                styles["Normal"]
            )
        )

        story.append(Spacer(1, 6))

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Generated by Company Risk Watch",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            datetime.now().strftime("%d-%m-%Y %H:%M"),
            styles["Normal"]
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer


# -----------------------------
# Home Page
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------
# Analyze
# -----------------------------
@app.route("/analyze", methods=["POST"])
def analyze():

    user_domain = request.form.get("domain", "")

    domain = clean_domain(user_domain)

    findings = []

    dns_result = check_dns(domain)
    findings.append(dns_result)

    https_result = check_https(domain)
    findings.append(https_result)

    tls_result = check_tls(domain)
    findings.append(tls_result)

    headers_result = check_security_headers(domain)
    findings.append(headers_result)

    vt_result, vt_risk = check_virustotal(domain)
    findings.append(vt_result)

    risk_score, risk_level = calculate_risk(
        findings,
        vt_risk
    )

    recommendations = make_recommendation(
        findings
    )

    return render_template(
        "result.html",
        domain=domain,
        risk_score=risk_score,
        risk_level=risk_level,
        findings=findings,
        recommendations=recommendations
    )


# -----------------------------
# Create Document
# -----------------------------
@app.route("/create-document", methods=["POST"])
def create_document():

    domain = request.form.get("domain", "")
    risk_score = request.form.get("risk_score", "0")

    return render_template(
        "report.html",
        domain=domain,
        risk_score=risk_score,
        generated_at=datetime.now().strftime(
            "%d-%m-%Y %H:%M"
        )
    )


# -----------------------------
# Download PDF
# -----------------------------
@app.route("/download-report", methods=["POST"])
def download_report():

    domain = request.form.get("domain", "")
    risk_score = request.form.get("risk_score", "0")
    risk_level = request.form.get("risk_level", "Unknown")

    findings = []

    for i in range(20):

        title = request.form.get(f"finding_title_{i}")

        if not title:
            continue

        findings.append({
            "status": request.form.get(
                f"finding_status_{i}", "Review"
            ),
            "title": title,
            "message": request.form.get(
                f"finding_message_{i}", ""
            )
        })

    recommendations = []

    for i in range(20):

        recommendation = request.form.get(
            f"recommendation_{i}"
        )

        if recommendation:
            recommendations.append(
                recommendation
            )

    pdf = build_pdf(
        domain,
        risk_score,
        risk_level,
        findings,
        recommendations
    )

    return send_file(
        pdf,
        as_attachment=True,
        download_name="company_risk_report.pdf",
        mimetype="application/pdf"
    )


# -----------------------------
# Run Application
# -----------------------------
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )