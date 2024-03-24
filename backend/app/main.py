from contextlib import asynccontextmanager

from fastapi import FastAPI
from core.settings import settings  # type: ignore
from api.main import api_router  # type: ignore

app = FastAPI(
    title=settings.APP_NAME, version="0.0.1", description="FastAPI Jaffby server"
)
app.include_router(api_router, prefix=settings.API_V1_STR)
