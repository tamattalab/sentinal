import os
from dotenv import load_dotenv

load_dotenv()

# API Authentication Key (for securing your endpoint)
MY_API_KEY = os.getenv("API_KEY", "sentinal-hackathon-2026")

# GUVI Callback URL
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
