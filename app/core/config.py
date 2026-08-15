from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    wazuh_api_base_url: str = "https://localhost:55000"
    wazuh_poll_interval_seconds: int = 5

    chroma_persist_directory: str = "./knowledge_base/chroma_store"
    chroma_collection_name: str = "mitre_attack"

    ollama_base_url: str = "http://localhost:11434"
    ollama_model_name: str = "llama3"

    checkpoint_database_path: str = "./checkpoints.sqlite"

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()