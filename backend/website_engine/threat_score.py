class ThreatScoreEngine:

    def __init__(self):
        pass

    def calculate(self, reports, ml_result=None):

        total_score = 0

        warnings = []

        recommendations = []

        score_breakdown = {}

        # -----------------------------
        # Security Modules
        # -----------------------------

        for report in reports:

            module = report.get("module", "Unknown")

            score = report.get("risk_score", 0)

            total_score += score

            score_breakdown[module] = score

            warnings.extend(report.get("warnings", []))

            recommendations.extend(report.get("recommendations", []))

        # -----------------------------
        # Machine Learning Score
        # -----------------------------

        ml_score = 0

        if ml_result is not None:

            probability = ml_result["phishing_probability"]

            if probability >= 99:
                ml_score = 60
            elif probability >= 95:
                ml_score = 50
            elif probability >= 85:
                ml_score = 40
            elif probability >= 70:
                ml_score = 25
            elif probability >= 50:
                ml_score = 15

            score_breakdown["Machine Learning"] = ml_score

            total_score += ml_score

        # -----------------------------
        # Normalize
        # -----------------------------

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

            "score_breakdown": score_breakdown,

            "warnings": warnings,

            "recommendations": recommendations
        }