import os
from pydantic_settings import BaseSettings  # type: ignore


class Settings(BaseSettings):
    APP_NAME: str = "Jaffby App Server"
    API_V1_STR: str = "/api/v1"
    POSTGRES_USER: str | None = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD: str | None = os.getenv("POSTGRES_PASSWORD")
    POSTGRES_DB: str | None = os.getenv("POSTGRES_DB")
    DEBUG: bool = True  # bool(os.getenv("DEBUG", False))
    SECRET_KEY: str | None = os.getenv("SECRET_KEY")
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 900
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ENCODING_ALGORITHM: str = "HS256"


settings = Settings()
