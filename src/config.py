import os
from dotenv import load_dotenv

load_dotenv()

# API Authentication Key (for securing your endpoint)
MY_API_KEY = os.getenv("API_KEY", "sentinal-hackathon-2026")

# GUVI Callback URL
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ── SLM (Small Language Model) Configuration ──────────────────────────
USE_SLM = os.getenv("USE_SLM", "false").lower() in ("true", "1", "yes")
SLM_MODEL_PATH = os.getenv("SLM_MODEL_PATH", "./SmolLM2-135M-Instruct")
SLM_TIMEOUT = int(os.getenv("SLM_TIMEOUT", "8"))  # seconds
