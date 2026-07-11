import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime


class SSLChecker:

    def __init__(self):
        pass

    def extract_domain(self, url):
        return urlparse(url).netloc

    def analyze(self, url):

        domain = self.extract_domain(url)

        report = {
            "module": "SSL Checker",
            "status": "SUCCESS",
            "risk_score": 0,
            "security_level": "LOW",
            "data": {},
            "warnings": [],
            "recommendations": []
        }

        try:

            context = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:

                    cert = secure_sock.getpeercert()

                    issuer = dict(x[0] for x in cert["issuer"]).get(
                        "organizationName", "Unknown"
                    )

                    expiry = datetime.strptime(
                        cert["notAfter"],
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    days_left = (expiry - datetime.now()).days

                    report["data"] = {
                        "ssl_available": True,
                        "issuer": issuer,
                        "expiry_date": expiry.strftime("%d-%m-%Y"),
                        "days_remaining": days_left
                    }

                    # Risk Analysis
                    if days_left < 0:
                        report["risk_score"] = 100
                        report["security_level"] = "CRITICAL"
                        report["warnings"].append("SSL certificate has expired.")
                        report["recommendations"].append("Do not trust this website.")

                    elif days_left < 30:
                        report["risk_score"] = 60
                        report["security_level"] = "MEDIUM"
                        report["warnings"].append(
                            "SSL certificate will expire soon."
                        )
                        report["recommendations"].append(
                            "Verify the website before entering sensitive information."
                        )

                    else:
                        report["risk_score"] = 5
                        report["security_level"] = "LOW"

        except Exception:

            report["status"] = "FAILED"

            report["risk_score"] = 100

            report["security_level"] = "CRITICAL"

            report["warnings"].append("SSL certificate not found.")

            report["recommendations"].append(
                "Avoid entering passwords or financial information."
            )

        return report


if __name__ == "__main__":

    checker = SSLChecker()

    url = "https://google.com"

    result = checker.analyze(url)

    print("\n================ SSL SECURITY REPORT ================\n")

    print(f"Module          : {result['module']}")
    print(f"Status          : {result['status']}")
    print(f"Risk Score      : {result['risk_score']}/100")
    print(f"Security Level  : {result['security_level']}")

    print("\n--------------- Certificate Details ----------------")

    for key, value in result["data"].items():
        print(f"{key:18}: {value}")

    print("\n-------------------- Warnings -----------------------")

    if result["warnings"]:
        for warning in result["warnings"]:
            print(f"⚠ {warning}")
    else:
        print("✅ No security warnings detected.")

    print("\n---------------- Recommendations -------------------")

    if result["recommendations"]:
        for recommendation in result["recommendations"]:
            print(f"✔ {recommendation}")
    else:
        print("✅ SSL configuration appears healthy.")