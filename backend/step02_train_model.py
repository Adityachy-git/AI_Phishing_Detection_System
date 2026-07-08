import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

df = pd.read_csv("datasets\PhiUSIIL_Phishing_URL_Dataset.csv")

# Remove text columns
df = df.drop(columns=[
    "FILENAME",
    "URL",
    "Domain",
    "TLD",
    "Title"
])

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print(feature_importance.head(20))

accuracy = accuracy_score(y_test, predictions)

print("Accuracy:", accuracy)

print("\nClassification Report:\n")

print(classification_report(y_test, predictions))

print("\nConfusion Matrix:\n")

print(confusion_matrix(y_test, predictions))

joblib.dump(model, "models/phishing_model.pkl")

print("Model Saved!")