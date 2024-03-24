from typing import Annotated
from datetime import datetime, timezone


from fastapi import APIRouter, Depends, HTTPException, Response, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from core.utils import get_db_session
from crud.users import (
    get_user_by_username,
    get_user_by_email,
    create_user,
    set_is_email_confirmed_and_is_active_true_on_user,
)
from crud.auth import (
    get_confirmation_token_by_token,
    set_is_used_true_on_confirmation_token,
)
from schemas.users import UserSchema, UserCreateSchema
from .utils import (
    authenticate_user,
    create_tokens_and_set_auth_cookies_in_response,
    clear_auth_cookies_in_response,
    generate_and_store_confirmation_token,
    send_confirmation_email,
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
    if user.is_email_confirmed == False:
        raise HTTPException(status_code=403, detail="Email address is not confirmed.")
    await create_tokens_and_set_auth_cookies_in_response(db, str(user.id), response)
    return {"message": "Logged in successfully"}


@router.get("/me", response_model=UserSchema)
async def me_route(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user


@router.post("/register")
async def register_route(
    user: UserCreateSchema,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    db_user_by_email = await get_user_by_email(db, email=user.email)
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user_by_username = await get_user_by_username(db, username=user.username)
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already registered")
    created_user = await create_user(db=db, user=user)
    token = await generate_and_store_confirmation_token(db, str(created_user.id))
    await send_confirmation_email(str(created_user.email), token)
    return {"message": "Confirmation email sent."}


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


@router.post("/confirm")
async def confirm_email_route(token: str, db: AsyncSession = Depends(get_db_session)):
    confirmation_token_from_db = await get_confirmation_token_by_token(db, token)
    current_time = datetime.now(timezone.utc).replace(tzinfo=None)
    if (
        confirmation_token_from_db is None
        or confirmation_token_from_db.is_used == True
        or confirmation_token_from_db.expires_at <= current_time
    ):
        raise HTTPException(status_code=400, detail="Wrong confirmation token.")
    await set_is_used_true_on_confirmation_token(db, str(confirmation_token_from_db.id))
    await set_is_email_confirmed_and_is_active_true_on_user(
        db, str(confirmation_token_from_db.user_id)
    )
    return {"message": "Email was confirmed successfully."}
