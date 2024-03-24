from fastapi import APIRouter

from .routers.auth import main as auth
from .routers import users

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
