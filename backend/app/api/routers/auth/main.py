from typing import Annotated
from pydantic import EmailStr

from fastapi import APIRouter, Depends, HTTPException, Response, BackgroundTasks, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from core.utils import get_db_session
from core.security import check_password
from crud.users import (
    get_user_by_username,
    get_user_by_email,
    create_user,
    set_is_email_confirmed_and_is_active_true_on_user,
    update_user_password,
)
from crud.auth import (
    set_is_used_true_on_token_from_email,
    set_is_used_true_on_all_email_confirmation_tokens_by_user_id,
)
from schemas.users import UserSchema, UserCreateSchema, UserPasswordResetSchema
from .utils import (
    authenticate_user,
    create_tokens_and_set_auth_cookies_in_response,
    clear_auth_cookies_in_response,
    generate_and_store_token_for_email,
    send_email_with_token,
)
from .dependencies import (
    get_current_active_user,
    validate_refresh_token_and_set_revoked_true,
    csrftoken_check,
    TokenFromEmailValidator,
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
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    db_user_by_email = await get_user_by_email(db, email=user.email)
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user_by_username = await get_user_by_username(db, username=user.username)
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already registered")
    created_user = await create_user(db=db, user=user)
    token = await generate_and_store_token_for_email(
        db, str(created_user.id), is_for_password_reset=False
    )
    background_tasks.add_task(
        send_email_with_token, str(created_user.email), token, False
    )
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


@router.post("/confirm-email")
async def confirm_email_route(
    data: Annotated[
        tuple[str, str, AsyncSession],
        Depends(TokenFromEmailValidator(is_for_reset_password=False)),
    ]
):
    token_id, user_id, db = data
    await set_is_used_true_on_token_from_email(
        db, token_id, is_for_password_reset=False
    )
    await set_is_email_confirmed_and_is_active_true_on_user(db, user_id)
    return {"message": "Email was confirmed successfully."}


@router.post("/resend-email-confirmation")
async def resend_confirmation_email_route(
    email: Annotated[EmailStr, Body(embed=True)],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    user = await get_user_by_email(db, email)
    if user and not user.is_email_confirmed:
        await set_is_used_true_on_all_email_confirmation_tokens_by_user_id(
            db, str(user.id)
        )
        token = await generate_and_store_token_for_email(
            db, str(user.id), is_for_password_reset=False
        )
        background_tasks.add_task(send_email_with_token, str(user.email), token, False)

    return {
        "message": "If an account with that email exists, a confirmation email has been sent."
    }


@router.post("/request-password-reset")
async def request_password_reset(
    email: Annotated[EmailStr, Body(embed=True)],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
):
    user = await get_user_by_email(db, email)
    if user and user.is_email_confirmed:
        token = await generate_and_store_token_for_email(
            db, str(user.id), is_for_password_reset=True
        )
        background_tasks.add_task(send_email_with_token, str(user.email), token, True)

    return {
        "message": "If an email address is associated with an account, a password reset link has been sent."
    }


@router.post("/reset-password")
async def reset_password_route(
    data: Annotated[
        tuple[str, str, AsyncSession],
        Depends(TokenFromEmailValidator(is_for_reset_password=True)),
    ],
    request_data: UserPasswordResetSchema,
):
    new_password = request_data.password
    token_id, user_id, db = data
    await set_is_used_true_on_token_from_email(db, token_id, is_for_password_reset=True)
    await update_user_password(db, new_password, user_id)
    return {"message": "Password was successfully reset."}
