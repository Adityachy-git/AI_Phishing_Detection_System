class ThreatScoreEngine:

    def __init__(self):
        pass

    def calculate(self, reports):

        total_score = 0
        warnings = []
        recommendations = []

        for report in reports:

            total_score += report.get("risk_score", 0)

            warnings.extend(report.get("warnings", []))

            recommendations.extend(report.get("recommendations", []))

        # Normalize score to 100
        total_score = min(total_score, 100)

        if total_score < 25:
            verdict = "SAFE"
            level = "LOW"

        elif total_score < 50:
            verdict = "SUSPICIOUS"
            level = "MEDIUM"

        elif total_score < 75:
            verdict = "LIKELY PHISHING"
            level = "HIGH"

        else:
            verdict = "PHISHING"
            level = "CRITICAL"

        return {

            "overall_score": total_score,

            "security_level": level,

            "verdict": verdict,

            "warnings": warnings,

            "recommendations": recommendations
        }