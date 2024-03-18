from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer
from core.settings import settings  # type: ignore
from api.main import api_router  # type: ignore

app = FastAPI(
    title=settings.APP_NAME, version="0.0.1", description="FastAPI Jaffby server"
)
app.include_router(api_router, prefix=settings.API_V1_STR)


# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# @app.get("/")
# async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
#     return {"token": token}
