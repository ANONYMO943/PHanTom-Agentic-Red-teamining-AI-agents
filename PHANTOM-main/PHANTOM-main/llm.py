"""Shared Gemini client used by all agents."""
import os
import time
from google import genai
from google.genai import types

def generate(prompt: str, model_name: str = "gemini-2.5-flash-lite") -> str:
    """Call Gemini and return text response. Retries on rate-limit (429)."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not set in .env file")
    client = genai.Client(api_key=api_key)
    for attempt in range(4):
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(max_output_tokens=2048)
            )
            return response.text
        except Exception as e:
            err = str(e)
            if "429" in err or "503" in err or "quota" in err.lower() or "RESOURCE_EXHAUSTED" in err or "UNAVAILABLE" in err:
                wait = 20 * (attempt + 1)
                print(f"[LLM] Rate limit hit — waiting {wait}s before retry {attempt+1}/3...")
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("Gemini API rate limit exceeded after retries. Try again in a few minutes.")
