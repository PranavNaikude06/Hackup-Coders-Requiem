import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

os.makedirs("app/core", exist_ok=True)

print("Loading dataset...")
df = pd.read_csv("d:/hackup/models/phising.csv")
print(f"Dataset: {df.shape[0]} rows, {df.shape[1]} columns")
print(f"Class distribution:\n{df['Result'].value_counts()}\n")

X = df.drop(columns=["Result"])
y = df["Result"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Tuned hyperparameters for 95%+ accuracy
print("Training optimized RandomForestClassifier...")
clf = RandomForestClassifier(
    n_estimators=300,          # More trees = more stable predictions
    max_depth=25,              # Prevent overfitting but allow deep splits
    min_samples_split=5,       # Require 5+ samples to split
    min_samples_leaf=2,        # Minimum 2 samples per leaf
    max_features='sqrt',       # Standard for classification
    class_weight='balanced',   # Handle any class imbalance
    random_state=42,
    n_jobs=-1                  # Use all CPU cores
)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\nTest Accuracy: {acc * 100:.2f}%")
print(f"\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Phishing (-1)", "Legitimate (1)"]))

# Cross-validation for robustness
cv_scores = cross_val_score(clf, X, y, cv=5, scoring='accuracy')
print(f"5-Fold Cross-Validation: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

# Feature importance (top 10)
importances = clf.feature_importances_
feat_imp = sorted(zip(X.columns, importances), key=lambda x: x[1], reverse=True)
print(f"\nTop 10 Feature Importances:")
for name, imp in feat_imp[:10]:
    print(f"  {name}: {imp:.4f}")

# Serialize
model_path = "app/core/rf_model.pkl"
joblib.dump(clf, model_path)
print(f"\nModel saved to {model_path}")
