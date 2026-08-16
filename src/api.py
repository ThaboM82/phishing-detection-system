import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Hybrid Phishing Detection API",
    version="1.0.0"
)

# Extract origins from environment or default to localhost / Vercel
allowed_origins = os.getenv(
    "CORS_ORIGINS", 
    "http://localhost:3000,http://127.0.0.1:8000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)