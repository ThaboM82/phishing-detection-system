
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from src.pipeline import PhishingDetectorPipeline

app = FastAPI(
    title="Phishing Detection API",
    description="Real-time URL phishing detection service using heuristic analysis and machine learning.",
    version="1.0.0"
)

# Enable CORS for React frontend (including Docker mapped port 8080)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = PhishingDetectorPipeline()

class URLRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"message": "Phishing Detection API is running."}

# Handle both routes to avoid breaking any client
@app.post("/analyze")
@app.post("/api/v1/inspect")
def inspect_url(payload: URLRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL string cannot be empty.")
    try:
        return pipeline.inspect_url(payload.url.strip())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error inspecting URL: {str(e)}")