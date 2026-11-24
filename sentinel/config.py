import os

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://sentinel:sentinel@localhost:5440/sentinel"
)
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "scripted-compromised")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "")
APPROVER_TOKEN = os.environ.get("APPROVER_TOKEN", "change-me")
