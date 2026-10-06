import joblib
import numpy as np

# Load model artifacts
model = joblib.load("model_artifacts/best_model.pkl")
scaler = joblib.load("model_artifacts/scaler.pkl")
label_encoder = joblib.load("model_artifacts/label_encoder.pkl")
feature_columns = joblib.load("model_artifacts/feature_columns.pkl")

print("Model features:", len(feature_columns))
print("Scaler features:", scaler.n_features_in_)
print("Model features:", model.n_features_in_)
print("Classes:", label_encoder.classes_)

# Create an empty test vector
test_features = {feature: 0.0 for feature in feature_columns}

# Example values
test_features["Destination Port"] = 22
test_features["Flow Duration"] = 166
test_features["Total Fwd Packets"] = 1
test_features["Total Backward Packets"] = 1

# Put features in EXACT training order
X = np.array([[test_features[col] for col in feature_columns]])

print("\nInput shape:", X.shape)

# Apply saved scaler
X_scaled = scaler.transform(X)

print("Scaled shape:", X_scaled.shape)

# Predict
prediction = model.predict(X_scaled)

# Convert numeric label → class name
label = label_encoder.inverse_transform(prediction)

print("\nPrediction:", prediction[0])
print("Label:", label[0])
