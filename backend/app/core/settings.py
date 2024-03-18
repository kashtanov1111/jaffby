import os
from pydantic_settings import BaseSettings  # type: ignore


class Settings(BaseSettings):
    APP_NAME: str = "Jaffby App Server"
    API_V1_STR: str = "/api/v1"
    POSTGRES_USER: str | None = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD: str | None = os.getenv("POSTGRES_PASSWORD")
    POSTGRES_DB: str | None = os.getenv("POSTGRES_DB")
    DEBUG: bool = True


settings = Settings()
