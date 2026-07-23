"""
Core — centralized configuration.

Responsibility (and ONLY responsibility):
    Load settings (from environment variables / .env) once, in one place.
    Every other module should import `settings` from here rather than
    reading os.environ directly.

Why this matters for security (M12 preview):
    Secrets (API keys, if any are ever added) should be pulled from
    environment variables via this module, never hardcoded in source
    files. This is also where you'd wire in a secret manager later if
    the project moves toward production deployment.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    wazuh_api_base_url: str = "https://localhost:55000"
    wazuh_poll_interval_seconds: int = 5

    chroma_persist_directory: str = "./knowledge_base/chroma_store"
    chroma_collection_name: str = "mitre_attack"

    ollama_base_url: str = "http://localhost:11434"
    ollama_model_name: str = "llama3"

    class Config:
        env_file = ".env"


settings = Settings()
