import joblib
import os

model = joblib.load("app/core/rf_model.pkl")

# 30 features
all_ones = [[1]*30]
all_neg_ones = [[-1]*30]

pred_ones = model.predict(all_ones)[0]
pred_neg_ones = model.predict(all_neg_ones)[0]

print(f"Prediction for features set to ALL 1s: {pred_ones}")
print(f"Prediction for features set to ALL -1s: {pred_neg_ones}")
