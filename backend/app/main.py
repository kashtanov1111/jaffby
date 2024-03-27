from pydantic import ValidationError

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from core.settings import settings
from api.main import api_router

app = FastAPI(
    title=settings.APP_NAME, version="0.0.1", description="FastAPI Jaffby server"
)
app.include_router(api_router, prefix=settings.API_VERSION_STR)
