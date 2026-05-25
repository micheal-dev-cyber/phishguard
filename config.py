import os
from dotenv import load_dotenv

load_dotenv()

# We keep this for non-AI constants
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
AI_MODEL = "meta-llama/llama-3-8b-instruct"