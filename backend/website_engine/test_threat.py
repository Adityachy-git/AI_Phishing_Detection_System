from threat_score import ThreatScoreEngine

engine = ThreatScoreEngine()

reports = [

    {
        "risk_score":20,
        "warnings":["Old domain"],
        "recommendations":["Verify owner"]
    },

    {
        "risk_score":10,
        "warnings":["SSL expires soon"],
        "recommendations":["Check certificate"]
    },

    {
        "risk_score":30,
        "warnings":["Suspicious keywords"],
        "recommendations":["Don't enter password"]
    }

]

result = engine.calculate(reports)

print(result)