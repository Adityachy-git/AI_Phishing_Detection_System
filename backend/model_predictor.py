import os
import joblib
import pandas as pd

from website_engine.url_analyzer import analyze_url


class ModelPredictor:

    def __init__(self):

        model_path = os.path.join(
            "models",
            "phishing_model_custom.pkl"
        )

        self.model = joblib.load(model_path)

    def predict(self, url):
        features = analyze_url(url)
        feature_df = pd.DataFrame([features])
        prediction = self.model.predict(feature_df)[0]
        probabilities = self.model.predict_proba(feature_df)[0]

        legitimate_probability = round(probabilities[0] * 100, 2)
        phishing_probability = round(probabilities[1] * 100, 2)

        return {

        "prediction": "PHISHING"
        if prediction == 1
        else "LEGITIMATE",

        "confidence": round(max(probabilities) * 100, 2),

        "legitimate_probability": legitimate_probability,

        "phishing_probability": phishing_probability,

        "features": features
    }


if __name__ == "__main__":

    predictor = ModelPredictor()

    url = input("Enter URL : ")

    result = predictor.predict(url)

    print("\n================ AI REPORT ================\n")

    print("Machine Learning")
    print("-" * 40)
    
    print(f"Prediction : {result['prediction']}")
    print(f"Confidence : {result['confidence']} %")
    
    print("\nProbability")
    print("-" * 40)
    
    print(f"Legitimate : {result['legitimate_probability']} %")
    print(f"Phishing   : {result['phishing_probability']} %")
    
    print("\nExtracted Features")
    print("-" * 40)

    for key, value in result["features"].items():
        print(f"{key:25}: {value}")