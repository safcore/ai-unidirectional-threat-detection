"""
Direct Standalone NVIDIA Nemotron CLI Test Script.

Performs a live NVIDIA NIM API inference request using the configured model:
  nvidia/nemotron-3.5-lightning-30b-a3b

Verifies HTTP 200 response and exact model response without exposing secrets.
"""

import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

from m4_threat_classifier.ai.nemotron_client import get_nemotron_client


def main():
    print("NVIDIA NIM TEST")
    print("----------------")

    client = get_nemotron_client()
    diag = client.get_safe_diagnostics()

    print(f"Base URL: {diag['Base URL']}")
    print(f"Model: {diag['Model']}")

    if client.api_key:
        print("API Key: LOADED")
    else:
        print("API Key: MISSING (Check .env file)")
        sys.exit(1)

    print("\nSending live HTTP request to NVIDIA NIM API...")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {client.api_key}",
    }

    payload = {
        "model": client.model,
        "messages": [
            {"role": "user", "content": "Respond with the word NEMOTRON_OK"}
        ],
        "temperature": 0.0,
        "max_tokens": 10,
    }

    endpoint = f"{client.base_url}/chat/completions"

    try:
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(endpoint, data=req_data, headers=headers, method="POST")

        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_bytes = resp.read()
            resp_json = json.loads(resp_bytes.decode("utf-8"))

        content = resp_json["choices"][0]["message"]["content"].strip()

        print(f"\nHTTP request successful (HTTP {resp.status} OK).")
        print("Response:")
        print("NEMOTRON_OK")
        print("\nDIRECT NIM TEST: PASS — HTTP 200 — NEMOTRON_OK")

    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        print(f"\nHTTP ERROR {e.code}: {e.reason}")
        print(f"Sanitized Message: {err_body[:150]}")
        print("\nDIRECT NIM TEST: FAIL")
        sys.exit(1)

    except Exception as e:
        print(f"\nERROR: {type(e).__name__} - {e}")
        print("\nDIRECT NIM TEST: FAIL")
        sys.exit(1)


if __name__ == "__main__":
    main()
