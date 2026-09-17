from flask import Flask, render_template, request
import socket
import ssl
import urllib.request
from urllib.parse import urlparse

app = Flask(__name__)


def clean_domain(value):
    value = value.strip()

    if not value:
        return ""

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)

    domain = parsed.hostname

    if not domain:
        return ""

    domain = domain.lower()

    # Require a domain such as google.com
    if "." not in domain:
        return ""

    return domain


def check_dns(domain):

    try:
        ip_address = socket.gethostbyname(domain)

        return {
            "name": "DNS Resolution",
            "status": "Pass",
            "details": f"Domain resolves to {ip_address}.",
            "points": 0
        }

    except socket.gaierror:

        return {
            "name": "DNS Resolution",
            "status": "Risk",
            "details": "The domain could not be resolved.",
            "points": 30
        }


def check_https(domain):

    try:

        request = urllib.request.Request(
            f"https://{domain}",
            method="HEAD",
            headers={
                "User-Agent": "CompanyRiskWatch/1.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            return {
                "name": "HTTPS",
                "status": "Pass",
                "details": f"HTTPS is available (HTTP {response.status}).",
                "points": 0
            }

    except Exception:

        return {
            "name": "HTTPS",
            "status": "Risk",
            "details": "HTTPS could not be verified.",
            "points": 20
        }


def check_tls(domain):

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=8
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                if certificate:

                    return {
                        "name": "TLS Certificate",
                        "status": "Pass",
                        "details": "A TLS certificate was successfully obtained.",
                        "points": 0
                    }

        return {
            "name": "TLS Certificate",
            "status": "Review",
            "details": "TLS certificate could not be verified.",
            "points": 10
        }

    except Exception:

        return {
            "name": "TLS Certificate",
            "status": "Risk",
            "details": "A TLS connection could not be established.",
            "points": 15
        }


def check_security_headers(domain):

    try:

        request = urllib.request.Request(
            f"https://{domain}",
            headers={
                "User-Agent": "CompanyRiskWatch/1.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

        required_headers = [
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options"
        ]

        missing = []

        for header in required_headers:

            if header not in headers:
                missing.append(header)

        if not missing:

            return {
                "name": "Security Headers",
                "status": "Pass",
                "details": "Common security headers were detected.",
                "points": 0
            }

        points = min(len(missing) * 5, 20)

        return {
            "name": "Security Headers",
            "status": "Review",
            "details": (
                "Some common security headers were not detected: "
                + ", ".join(missing)
            ),
            "points": points
        }

    except Exception:

        return {
            "name": "Security Headers",
            "status": "Unknown",
            "details": "Security headers could not be checked.",
            "points": 5
        }


def calculate_risk(findings):

    total_points = sum(
        finding["points"]
        for finding in findings
    )

    score = min(total_points, 100)

    if score < 20:
        level = "Low"

    elif score < 50:
        level = "Medium"

    else:
        level = "High"

    return score, level


@app.route("/")
def home():

    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    user_input = request.form.get(
        "company",
        ""
    )

    domain = clean_domain(user_input)

    if not domain:

        return render_template(
            "index.html",
            error=(
                "Please enter a complete domain such as "
                "google.com or microsoft.com."
            )
        )

    findings = []

    findings.append(
        check_dns(domain)
    )

    findings.append(
        check_https(domain)
    )

    findings.append(
        check_tls(domain)
    )

    findings.append(
        check_security_headers(domain)
    )

    risk_score, risk_level = calculate_risk(
        findings
    )

    if risk_level == "Low":

        recommendation = (
            "The checked public configuration shows "
            "few issues. Continue regular security "
            "monitoring and keep security controls updated."
        )

    elif risk_level == "Medium":

        recommendation = (
            "Review the reported configuration findings "
            "and strengthen the affected security controls."
        )

    else:

        recommendation = (
            "Several security checks require attention. "
            "Investigate the reported findings and perform "
            "an authorized security assessment."
        )

    return render_template(
        "result.html",
        domain=domain,
        risk_score=risk_score,
        risk_level=risk_level,
        findings=findings,
        recommendation=recommendation
    )


if __name__ == "__main__":

    app.run(debug=True)