import re
import sys
import os
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai_engine import AIEngine


class LinkAnalyzer:

    def __init__(self):

        self.suspicious_tlds = [
            ".xyz", ".top", ".click", ".buzz", ".work", ".download",
            ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq"
        ]

        self.suspicious_keywords = [
            "login", "signin", "verify", "verification", "account",
            "secure", "security", "update", "confirm", "password",
            "credential", "wallet", "payment", "recover", "suspended",
            "unlock"
        ]

        # Website AI Engine
        self.website_engine = AIEngine()


    # ---------------------------------------------------------
    # URL EXTRACTION
    # ---------------------------------------------------------

    def extract_urls(self, text):

        if not text:
            return []

        url_pattern = r"https?://[^\s<>\"]+"

        urls = re.findall(url_pattern, text)

        cleaned_urls = []

        for url in urls:

            url = url.rstrip(".,!?;:)]}")

            if url not in cleaned_urls:
                cleaned_urls.append(url)

        return cleaned_urls


    # ---------------------------------------------------------
    # IP ADDRESS CHECK
    # ---------------------------------------------------------

    def is_ip_address(self, hostname):

        if not hostname:
            return False

        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        return bool(re.match(ip_pattern, hostname))


    # ---------------------------------------------------------
    # BASIC URL ANALYSIS
    # ---------------------------------------------------------

    def analyze_url(self, url):

        result = {

            "url": url,

            "valid": False,

            "score": 0,

            "risk_level": "LOW",

            "indicators": []

        }

        try:

            parsed = urlparse(url)

            if parsed.scheme not in ["http", "https"]:

                result["indicators"].append(
                    "URL does not use HTTP or HTTPS."
                )

                result["score"] += 15


            if not parsed.netloc:

                result["indicators"].append(
                    "URL does not contain a valid domain."
                )

                result["score"] += 25

                result["score"] = min(result["score"], 100)

                result["risk_level"] = "HIGH"

                return result


            result["valid"] = True

            hostname = (parsed.hostname or "").lower()


            # URL LENGTH
            url_length = len(url)

            if url_length > 200:

                result["score"] += 10

                result["indicators"].append(
                    "Very long URL detected."
                )

            elif url_length > 120:

                result["score"] += 5

                result["indicators"].append(
                    "Long URL detected."
                )


            # HTTPS
            if parsed.scheme == "http":

                result["score"] += 8

                result["indicators"].append(
                    "URL does not use HTTPS."
                )


            # IP ADDRESS
            if self.is_ip_address(hostname):

                result["score"] += 25

                result["indicators"].append(
                    "URL uses an IP address instead of a domain."
                )


            # SUSPICIOUS TLD
            for tld in self.suspicious_tlds:

                if hostname.endswith(tld):

                    result["score"] += 15

                    result["indicators"].append(
                        f"Suspicious top-level domain detected: {tld}"
                    )

                    break


            # SUBDOMAINS
            domain_parts = hostname.split(".")

            if len(domain_parts) >= 4:

                result["score"] += 10

                result["indicators"].append(
                    "URL contains many subdomains."
                )


            # @ SYMBOL
            if "@" in url:

                result["score"] += 20

                result["indicators"].append(
                    "URL contains an @ symbol."
                )


            # HYPHENS
            hyphen_count = hostname.count("-")

            if hyphen_count >= 3:

                result["score"] += 10

                result["indicators"].append(
                    "Domain contains many hyphens."
                )

            elif hyphen_count >= 1:

                result["score"] += 3


            # DOTS
            dot_count = hostname.count(".")

            if dot_count >= 4:

                result["score"] += 8

                result["indicators"].append(
                    "Domain contains many dots."
                )


            # SUSPICIOUS KEYWORDS
            url_lower = url.lower()

            matched_keywords = []

            for keyword in self.suspicious_keywords:

                if keyword in url_lower:

                    matched_keywords.append(keyword)


            if matched_keywords:

                keyword_score = min(
                    len(matched_keywords) * 4,
                    16
                )

                result["score"] += keyword_score

                result["indicators"].append(
                    "Suspicious URL keywords detected: "
                    + ", ".join(matched_keywords)
                )


            # ENCODED CHARACTERS
            if "%" in url:

                result["score"] += 5

                result["indicators"].append(
                    "URL contains encoded characters."
                )


            # URL DEPTH
            path = parsed.path or ""

            path_parts = [
                part
                for part in path.split("/")
                if part
            ]

            if len(path_parts) >= 5:

                result["score"] += 8

                result["indicators"].append(
                    "URL contains a deep path structure."
                )


            # QUERY STRING
            if parsed.query:

                if len(parsed.query) > 100:

                    result["score"] += 5

                    result["indicators"].append(
                        "URL contains a large query string."
                    )


            # FINAL SCORE
            result["score"] = min(
                result["score"],
                100
            )


            if result["score"] < 25:

                result["risk_level"] = "LOW"

            elif result["score"] < 50:

                result["risk_level"] = "MEDIUM"

            elif result["score"] < 75:

                result["risk_level"] = "HIGH"

            else:

                result["risk_level"] = "CRITICAL"


        except Exception as error:

            result["valid"] = False

            result["score"] = 50

            result["risk_level"] = "HIGH"

            result["indicators"].append(
                f"URL analysis failed: {str(error)}"
            )


        return result


    # ---------------------------------------------------------
    # FULL LINK ANALYSIS
    # ---------------------------------------------------------

    def analyze(self, links=None, body=""):

        result = {

            "module": "Link Analyzer",

            "status": "SUCCESS",

            "data": {

                "link_count": 0,

                "links": [],

                "highest_risk_score": 0,

                "highest_risk_level": "LOW"

            },

            "warnings": [],

            "recommendations": []

        }


        try:

            # -------------------------------------------------
            # GET LINKS
            # -------------------------------------------------

            if links is None:

                links = self.extract_urls(body)

            else:

                links = list(links)


            # Remove duplicates
            unique_links = []

            for link in links:

                if link not in unique_links:

                    unique_links.append(link)


            links = unique_links

            result["data"]["link_count"] = len(links)


            # -------------------------------------------------
            # ANALYZE EACH LINK
            # -------------------------------------------------

            for link in links:

                # Basic URL analysis
                link_result = self.analyze_url(link)


                # -------------------------------------------------
                # WEBSITE AI ANALYSIS
                # -------------------------------------------------

                website_result = None

                if link_result["valid"]:

                    try:

                        website_result = self.website_engine.analyze(
                            link
                        )

                    except Exception as error:

                        website_result = {

                            "status": "FAILED",

                            "error": str(error)

                        }


                link_result["website_analysis"] = website_result


                # -------------------------------------------------
                # STORE RESULT
                # -------------------------------------------------

                result["data"]["links"].append(
                    link_result
                )


                # Highest basic URL risk
                if (
                    link_result["score"]
                    >
                    result["data"]["highest_risk_score"]
                ):

                    result["data"]["highest_risk_score"] = (
                        link_result["score"]
                    )

                    result["data"]["highest_risk_level"] = (
                        link_result["risk_level"]
                    )


                # -------------------------------------------------
                # WEBSITE WARNINGS
                # -------------------------------------------------

                if website_result:

                    if website_result.get("status") == "SUCCESS":

                        threat = website_result.get(
                            "threat_analysis",
                            {}
                        )

                        website_score = threat.get(
                            "overall_score",
                            0
                        )

                        website_verdict = threat.get(
                            "verdict",
                            ""
                        )


                        # Add website risk indicator
                        if website_score >= 50:

                            link_result["indicators"].append(
                                f"Website AI detected high risk "
                                f"(score: {website_score}/100)."
                            )

                        elif website_score >= 25:

                            link_result["indicators"].append(
                                f"Website AI detected suspicious activity "
                                f"(score: {website_score}/100)."
                            )


                        # Phishing verdict
                        if website_verdict in [
                            "PHISHING",
                            "LIKELY PHISHING"
                        ]:

                            result["warnings"].append(
                                f"Website AI classified link as "
                                f"{website_verdict}: {link}"
                            )


            # -------------------------------------------------
            # GENERAL LINK WARNINGS
            # -------------------------------------------------

            if len(links) > 0:

                result["warnings"].append(
                    f"{len(links)} link(s) detected in the email."
                )


            # High-risk basic links
            high_risk_links = [

                link

                for link in result["data"]["links"]

                if link["score"] >= 50

            ]


            if high_risk_links:

                result["warnings"].append(
                    f"{len(high_risk_links)} high-risk "
                    f"link(s) detected."
                )


            # -------------------------------------------------
            # RECOMMENDATIONS
            # -------------------------------------------------

            if high_risk_links:

                result["recommendations"].append(
                    "Do not click high-risk links until "
                    "they are independently verified."
                )

            elif links:

                result["recommendations"].append(
                    "Verify email links before clicking them."
                )

            else:

                result["recommendations"].append(
                    "No links were detected in the email."
                )


        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Link analysis failed: {str(error)}"
            )


        return result


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    analyzer = LinkAnalyzer()


    body = """
    Please verify your account immediately.

    https://example.com/verify-account

    """


    report = analyzer.analyze(
        body=body
    )


    print("\n" + "=" * 70)
    print("LINK ANALYSIS")
    print("=" * 70)


    print(
        "\nTotal Links:",
        report["data"]["link_count"]
    )


    for link in report["data"]["links"]:

        print("\nURL:")
        print(link["url"])

        print(
            "Basic Risk:",
            link["risk_level"],
            f"({link['score']}/100)"
        )

        print("\nIndicators:")

        for indicator in link["indicators"]:

            print(" -", indicator)


        website = link.get(
            "website_analysis"
        )


        if website and website.get("status") == "SUCCESS":

            threat = website["threat_analysis"]

            print("\nWebsite AI:")

            print(
                " ML Prediction:",
                website["machine_learning"]["prediction"]
            )

            print(
                " Threat Score:",
                threat["overall_score"]
            )

            print(
                " Security Level:",
                threat["security_level"]
            )

            print(
                " Verdict:",
                threat["verdict"]
            )


    print("\nWarnings:")

    for warning in report["warnings"]:

        print("⚠", warning)