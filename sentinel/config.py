import os

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://sentinel:sentinel@localhost:5440/sentinel"
)
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "scripted-compromised")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "")
APPROVER_TOKEN = os.environ.get("APPROVER_TOKEN", "change-me")
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.7"))
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "180"))
LLM_NUM_CTX = int(os.environ.get("LLM_NUM_CTX", "8192"))
SCENARIOS_DIR = os.environ.get("SCENARIOS_DIR", "scenarios")
