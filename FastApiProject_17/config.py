from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:123@localhost:5432/notesdb"
    REDIS_URL: str = "redis://localhost:6379"
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    CACHE_TTL: int = 300
    NOTES_CACHE_PREFIX: str = "notes:"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings() 