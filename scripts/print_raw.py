import os
import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
_backend_dir = _project_root / "backend"
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from app.env_loader import load_env
load_env()
from app.alert_store import AlertStore
from app.ai_service import _build_analysis_prompt
from openai import OpenAI

store = AlertStore(str(_backend_dir / "data" / "alerts.json"))
alert = store.get_by_id("ALT-001")
prompt = _build_analysis_prompt(alert)

client = OpenAI(
    base_url=os.environ.get("NVIDIA_BASE_URL"),
    api_key=os.environ.get("NVIDIA_API_KEY"),
    timeout=120
)
resp = client.chat.completions.create(
    model=os.environ.get("NVIDIA_MODEL"),
    messages=[{"role": "user", "content": prompt}],
    temperature=0.2,
    max_tokens=2048
)
print("=== START RAW RESPONSE ===")
print(resp.choices[0].message.content)
print("=== END RAW RESPONSE ===")
