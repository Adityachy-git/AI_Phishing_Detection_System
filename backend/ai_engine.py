import json

from utils.validator import is_valid_url
from utils.loggers import log

from model_predictor import ModelPredictor

from website_engine.ssl_checker import SSLChecker
from website_engine.dns_checker import DNSChecker
from website_engine.whois_checker import WhoisChecker
from website_engine.keyword_checker import KeywordChecker
from website_engine.threat_score import ThreatScoreEngine


class AIEngine:
    """
    Master AI Engine

    Coordinates:
    - Machine Learning
    - SSL Analysis
    - DNS Analysis
    - WHOIS Analysis
    - Keyword Analysis
    - Threat Score
    """

    def __init__(self):

        self.model = ModelPredictor()

        self.ssl_checker = SSLChecker()

        self.dns_checker = DNSChecker()

        self.whois_checker = WhoisChecker()

        self.keyword_checker = KeywordChecker()

        self.threat_engine = ThreatScoreEngine()

    def analyze(self, url):

        try:

            # -----------------------------
            # Validate URL
            # -----------------------------

            if not is_valid_url(url):

                return {
                    "status": "FAILED",
                    "message": "Invalid URL."
                }

            log("Running Machine Learning...")

            ml_result = self.model.predict(url)

            log("Checking SSL...")

            ssl_result = self.ssl_checker.analyze(url)

            log("Checking DNS...")

            dns_result = self.dns_checker.analyze(url)

            log("Checking WHOIS...")

            whois_result = self.whois_checker.analyze(url)

            log("Checking Keywords...")

            keyword_result = self.keyword_checker.analyze(url)

            log("Calculating Threat Score...")

            threat_result = self.threat_engine.calculate(
                [
                    ssl_result,
                    dns_result,
                    whois_result,
                    keyword_result
                ],
                ml_result
            )

            log("Analysis Completed.")

            return {

                "status": "SUCCESS",

                "url": url,

                "machine_learning": ml_result,

                "ssl": ssl_result,

                "dns": dns_result,

                "whois": whois_result,

                "keywords": keyword_result,

                "threat_analysis": threat_result
            }

        except Exception as e:

            return {

                "status": "FAILED",

                "error": str(e)
            }


if __name__ == "__main__":

    engine = AIEngine()

    url = input("\nEnter URL : ")

    report = engine.analyze(url)

    # -----------------------------
    # Failed Analysis
    # -----------------------------

    if report["status"] == "FAILED":

        print("\nAnalysis Failed")
        print(report.get("message", report.get("error")))

        exit()

    # -----------------------------
    # Pretty Report
    # -----------------------------

    print("\n" + "=" * 80)
    print("                 AI PHISHING DETECTION REPORT")
    print("=" * 80)

    print(f"\nURL")
    print("-" * 80)
    print(report["url"])

    # -----------------------------
    # Machine Learning
    # -----------------------------

    ml = report["machine_learning"]

    print("\nMachine Learning")
    print("-" * 80)

    print(f"Prediction              : {ml['prediction']}")
    print(f"Confidence              : {ml['confidence']} %")
    print(f"Legitimate Probability  : {ml['legitimate_probability']} %")
    print(f"Phishing Probability    : {ml['phishing_probability']} %")

    print("\nScore Breakdown")
    print("-" * 80)
    threat = report["threat_analysis"]

    for module, score in threat["score_breakdown"].items():
        print(f"{module:25} +{score}")

    print("\nURL Feature Summary") 
    print("-" * 80)
    features = ml["features"]
    
    for key, value in features.items():
        print(f"{key:30}: {value}")
    # -----------------------------
    # Threat Analysis
    # -----------------------------

    threat = report["threat_analysis"]

    print("\nThreat Analysis")
    print("-" * 80)

    print(f"Overall Score           : {threat['overall_score']}/100")
    print(f"Security Level          : {threat['security_level']}")
    print(f"Verdict                 : {threat['verdict']}")

    # -----------------------------
    # Warnings
    # -----------------------------

    print("\nWarnings")
    print("-" * 80)

    if threat["warnings"]:

        for warning in threat["warnings"]:

            print(f"⚠ {warning}")

    else:

        print("No security warnings detected.")

    # -----------------------------
    # Recommendations
    # -----------------------------

    print("\nOverall Recommendation") 
    print("-" * 80)

    verdict = threat["verdict"]
    
    if verdict == "PHISHING":
        print("🚨 HIGH RISK")
        print("Do NOT visit this website.")
    elif verdict == "LIKELY PHISHING":
        print("⚠ HIGH RISK")
        print("Verify the website carefully before proceeding.Avoid Entering Passwords")
    elif verdict == "SUSPICIOUS":
        print("🟡 SUSPICIOUS")
        print("Proceed with caution.Careful when Entering Sensitive info.")
    else:
        print("🟢 SAFE")
        print("No major security concerns detected.")