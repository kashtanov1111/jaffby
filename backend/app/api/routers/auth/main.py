from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from core.utils import get_db_session
from crud.users import get_user_by_username, get_user_by_email, create_user
from schemas.users import UserSchema, UserCreateSchema
from .utils import (
    authenticate_user,
    create_tokens_and_set_auth_cookies_in_response,
    clear_auth_cookies_in_response,
)
from .dependencies import (
    get_current_active_user,
    validate_refresh_token_and_set_revoked_true,
    csrftoken_check,
)
from models.users import User

router = APIRouter()


@router.post("/login")
async def login_route(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    user = await authenticate_user(db, form_data.username, form_data.password)
    await create_tokens_and_set_auth_cookies_in_response(db, str(user.id), response)
    return {"message": "Logged in successfully"}


@router.get("/me", response_model=UserSchema)
async def me_route(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user


@router.post("/register", response_model=UserSchema)
async def register_route(
    user: UserCreateSchema,
    response: Response,
    db: AsyncSession = Depends(get_db_session),
):
    db_user_by_email = await get_user_by_email(db, email=user.email)
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user_by_username = await get_user_by_username(db, username=user.username)
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already registered")
    created_user = await create_user(db=db, user=user)
    await create_tokens_and_set_auth_cookies_in_response(
        db, str(created_user.id), response
    )
    return created_user


@router.post("/refresh", dependencies=[Depends(csrftoken_check)])
async def refresh_token_route(
    response: Response,
    user_id: Annotated[str, Depends(validate_refresh_token_and_set_revoked_true)],
    db: AsyncSession = Depends(get_db_session),
):
    await create_tokens_and_set_auth_cookies_in_response(db, user_id, response)
    return {"message": "Successfully refreshed tokens."}


@router.post(
    "/logout",
    dependencies=[
        Depends(csrftoken_check),
        Depends(get_current_active_user),
        Depends(validate_refresh_token_and_set_revoked_true),
    ],
)
async def logout_route(response: Response):
    await clear_auth_cookies_in_response(response)
    return {"message": "Successfully logged out"}
