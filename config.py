import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
API_SECRET_KEY = os.getenv("API_SECRET_KEY", "default-secret-key")
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
