import os
from pydantic_settings import BaseSettings  # type: ignore


class Settings(BaseSettings):
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 900
    API_VERSION_STR: str = "/api/v1"
    APP_NAME: str = "Jaffby App Server"
    DEBUG: bool = True  # bool(os.getenv("DEBUG", False))
    DOMAIN_NAME: str = "jaffby.com"
    EMAIL_CONFIRMATION_TOKEN_EXPIRE_HOURS: int = 24
    JWT_ENCODING_ALGORITHM: str = "HS256"
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 15
    POSTGRES_DB: str | None = os.getenv("POSTGRES_DB")
    POSTGRES_PASSWORD: str | None = os.getenv("POSTGRES_PASSWORD")
    POSTGRES_USER: str | None = os.getenv("POSTGRES_USER")
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SECRET_KEY: str | None = os.getenv("SECRET_KEY")
    SMTP_HOST_PASSWORD: str | None = os.getenv("SMTP_HOST_PASSWORD")
    SMTP_HOST_USER: str | None = os.getenv("SMTP_HOST_USER")
    SMTP_HOST: str | None = os.getenv("SMTP_HOST")
    SMTP_PORT: int = 587


settings = Settings()
