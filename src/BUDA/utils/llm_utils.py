import openai
import requests
import re
import logging
from flask import jsonify
from ..utils.config_utils import load_llm_config

_LOG = logging.getLogger(__name__)
_REQUEST_TIMEOUT_SECONDS = 30.0

def get_llm_response(messages, model="gpt-3.5-turbo", provider="openai"):
    """
    Sends a request to the selected AI model (OpenAI or LM Studio).
    
    :param messages: List of messages to send as context.
    :param model: Model name (default: "gpt-3.5-turbo").
    :param provider: Choose between "openai" (default) or "lmstudio".
    :return: Processed AI response.
    """
    try:
        config = load_llm_config()
        provider = config["provider"]
        model = config["model_name"]
        api_key = config["api_key"] if provider == "openai" else None
        lmstudio_url = config["lmstudio_url"] if provider == "lmstudio" else "http://localhost:1234/v1/chat/completions"

        if provider == "openai":
            openai.api_key = api_key
            response = openai.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=500,
                temperature=0.7,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
            result = response.choices[0].message.content.strip()

        elif provider == "lmstudio":
            LM_STUDIO_URL = lmstudio_url

            payload = {
                "model": model,
                "messages": messages,
                "max_tokens": 500,
                "temperature": 0.7
            }

            response = requests.post(
                LM_STUDIO_URL,
                json=payload,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            result = response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()

        else:
            return jsonify({"error": "Invalid LLM provider selected"}), 400

        # Clean and extract JSON if needed
        cleaned_result = re.sub(r"```json\s*|\s*```", "", result, flags=re.IGNORECASE)
        return cleaned_result

    except Exception:
        # El detalle puede contener fragmentos del proveedor o de la red
        # interna: queda en el log del servidor y no cruza la respuesta HTTP.
        _LOG.exception("Falló la solicitud al proveedor LLM")
        return jsonify({"error": "LLM request failed"}), 500
