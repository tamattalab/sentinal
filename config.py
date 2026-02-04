import os
from dotenv import load_dotenv

load_dotenv()

# OpenRouter API Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "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")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Free models on OpenRouter (prioritized list)
FREE_MODELS = [
    "meta-llama/llama-3.2-3b-instruct:free",
    "google/gemma-2-9b-it:free",
    "mistralai/mistral-7b-instruct:free",
    "huggingfaceh4/zephyr-7b-beta:free"
]

# API Authentication Key (for securing your endpoint)
MY_API_KEY = os.getenv("MY_API_KEY", "sentinal-hackathon-2026")

# GUVI Callback URL
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
