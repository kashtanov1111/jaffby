import redis.asyncio as redis  # type: ignore
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi_limiter import FastAPILimiter  # type: ignore

from core.settings import settings
from core.utils import CustomRateLimiter
from api.main import api_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    redis_connection = redis.from_url("redis://redis:6379", encoding="utf8")
    await FastAPILimiter.init(redis_connection)
    yield
    await FastAPILimiter.close()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.0.1",
    description="FastAPI Jaffby server",
    lifespan=lifespan,
)
app.include_router(api_router, prefix=settings.API_VERSION_STR)


@app.get("/index", dependencies=[Depends(CustomRateLimiter(times=2, seconds=5))])
async def index():
    return {"mssg": "hello"}
