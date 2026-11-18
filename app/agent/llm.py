
import os
import requests

from dotenv import load_dotenv
from google import genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL")

OLLAMA_HOST = os.getenv(
    "OLLAMA_HOST",
    "http://localhost:11434"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5-coder:1.5b"
)

AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()

# Reuse Gemini client instead of creating one for every request.
_gemini_client = None

# Remember Gemini failure during the current server session.
_gemini_available = True

# Avoid repeating the same failure message.
_gemini_failure_logged = False


def call_gemini(prompt: str) -> str:
    global _gemini_client

    if not GEMINI_API_KEY or not GEMINI_MODEL:
        raise RuntimeError("Gemini configuration missing")

    if _gemini_client is None:
        _gemini_client = genai.Client(
            api_key=GEMINI_API_KEY
        )

    response = _gemini_client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt
    )

    if not response.text:
        raise RuntimeError("Empty Gemini response")

    return response.text


def call_ollama(prompt: str) -> str:
    response = requests.post(
        f"{OLLAMA_HOST.rstrip('/')}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        },
        timeout=180
    )

    response.raise_for_status()

    result = response.json().get("response", "")

    if not result:
        raise RuntimeError("Empty Ollama response")

    return result


def generate_analysis(prompt: str) -> dict:
    global _gemini_available
    global _gemini_failure_logged

    # Explicit Ollama configuration.
    if AI_PROVIDER == "ollama":
        return {
            "provider": "ollama",
            "response": call_ollama(prompt)
        }

    # Use Ollama directly after Gemini has failed once.
    if not _gemini_available:
        return {
            "provider": "ollama",
            "response": call_ollama(prompt)
        }

    try:
        result = call_gemini(prompt)

        return {
            "provider": "gemini",
            "response": result
        }

    except Exception as error:
        _gemini_available = False

        if not _gemini_failure_logged:
            print(
                f"Gemini unavailable: {type(error).__name__}. "
                "Using Ollama for remaining requests."
            )
            _gemini_failure_logged = True

        result = call_ollama(prompt)

        return {
            "provider": "ollama",
            "response": result
        }
