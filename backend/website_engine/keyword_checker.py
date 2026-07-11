from urllib.parse import urlparse


class KeywordChecker:

    def __init__(self):

        self.suspicious_keywords = [

            "login",
            "signin",
            "verify",
            "verification",
            "secure",
            "security",
            "update",
            "account",
            "bank",
            "paypal",
            "wallet",
            "payment",
            "confirm",
            "password",
            "otp",
            "gift",
            "bonus",
            "free",
            "invoice",
            "refund",
            "crypto",
            "bitcoin",
            "support",
            "admin",
            "webscr",
            "authenticate"

        ]

    def analyze(self, url):

        url_lower = url.lower()

        found = []

        for word in self.suspicious_keywords:

            if word in url_lower:
                found.append(word)

        risk_score = min(len(found) * 8, 100)

        if risk_score == 0:
            level = "LOW"
        elif risk_score < 40:
            level = "MEDIUM"
        else:
            level = "HIGH"

        report = {

            "module": "Keyword Checker",
            "status": "SUCCESS",
            "risk_score": risk_score,
            "security_level": level,

            "data": {
                "matched_keywords": found,
                "total_matches": len(found)
            },

            "warnings": [],
            "recommendations": []

        }

        if found:

            report["warnings"].append(
                f"Detected {len(found)} suspicious keyword(s)."
            )

            report["recommendations"].append(
                "Verify the authenticity of this website before entering credentials."
            )

        return report


if __name__ == "__main__":

    checker = KeywordChecker()

    url = "https://this-domain-does-not-exist-123456.com"

    result = checker.analyze(url)

    print("\n========== KEYWORD SECURITY REPORT ==========\n")

    print(f"Risk Score : {result['risk_score']}/100")
    print(f"Security   : {result['security_level']}")

    print("\nMatched Keywords:")

    if result["data"]["matched_keywords"]:
        for word in result["data"]["matched_keywords"]:
            print(f" • {word}")
    else:
        print("None")

    print("\nWarnings:")

    if result["warnings"]:
        for warning in result["warnings"]:
            print(f"⚠ {warning}")
    else:
        print("No warnings.")