from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import pickle
from utils import extract_features_from_url  # Ensure this exists
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

# ----------------------------
# Initialize FastAPI
# ----------------------------
app = FastAPI(
    title="Phishing Website Detection API",
    description="Detect phishing websites using a trained Machine Learning model.",
    version="0.1.0"
)

# ----------------------------
# Allow React frontend (CORS)
# ----------------------------
origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Load the trained ML model
# ----------------------------
MODEL_PATH = "model/model.pkl"

try:
    with open(MODEL_PATH, "rb") as file:
        model = pickle.load(file)
    print("✅ Model loaded successfully!")
except Exception as e:
    print("❌ Error loading model:", e)
    model = None

# ----------------------------
# Request/Response Models
# ----------------------------
class UrlInput(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    prediction: str
    probability: float

# ----------------------------
# Prediction Endpoint
# ----------------------------
@app.post("/predict", response_model=PredictionResponse)
def predict_url(data: UrlInput):
    url = data.url.strip()
    
    if not url:
        return {"prediction": "Invalid URL", "probability": 0.0}

    if model is None:
        return {"prediction": "Model not loaded", "probability": 0.0}

    try:
        # ----------------------------
        # Extract features
        # ----------------------------
        features = extract_features_from_url(url)

        # Ensure features are 2D for the model
        if len(features.shape) == 1:
            features = features.reshape(1, -1)

        # ----------------------------
        # Optional: apply scaler if your model used one
        # ----------------------------
        # features = scaler.transform(features)

        # ----------------------------
        # Predict phishing probability
        # ----------------------------
        proba = model.predict_proba(features)[0][1]  # probability of phishing
        proba = np.clip(proba, 0, 1)  # Ensure probability is between 0 and 1
        probability = round(proba * 100, 2)

        # ----------------------------
        # Interpret label
        # ----------------------------
        if probability < 60:
            label = "✅ Safe Website"
        elif probability < 85:
            label = "⚠️ Suspicious Website"
        else:
            label = "🚨 Phishing Website"

        # ----------------------------
        # Optional whitelist for known safe domains
        # ----------------------------
        safe_domains = ["github.com", "google.com", "wikipedia.org", "youtube.com", "linkedin.com"]
        if any(domain in url for domain in safe_domains):
            label = "✅ Safe Website"
            probability = 0.0

        return {"prediction": label, "probability": probability}

    except Exception as e:
        print("Prediction error:", e)
        return {"prediction": "Error processing URL", "probability": 0.0}

# ----------------------------
# Root Endpoint
# ----------------------------
@app.get("/")
def root():
    return {
        "message": "Phishing Website Detection API 🚀",
        "usage": "Send a POST request to /predict with {'url': '<website_url>'}"
    }
