from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    BackgroundTasks,
)
from fastapi.security import OAuth2PasswordRequestForm


from crud.users import UserCRUD
from crud.auth import TokenForEmailCRUD, RefreshTokenCRUD
from schemas.users import (
    UserSchema,
    UserCreateSchema,
    UserNewPasswordSchema,
    UserNewUsernameSchema,
)
from .utils import (
    authenticate_user,
    create_tokens_and_set_auth_cookies_in_response,
    clear_auth_cookies_in_response,
)
from .dependencies import (
    get_current_user,
    csrftoken_check,
    GetDbSessionDep,
    GetCurrentUserDep,
    CustomRateLimiterDepends5,
    CustomRateLimiterDepends10,
    CustomRateLimiterDepends20,
    ValidateRefreshTokenFromCookieDep,
    VerifyPasswordForImportantChangesDep,
    EmailStrEmbeddedDep,
)
from .classes import TokenForEmail, TokenForEmailDep, TokenForEmailPassResetDep

router = APIRouter()


@router.post("/login", dependencies=[CustomRateLimiterDepends10])
async def login_route(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: GetDbSessionDep,
) -> dict[str, str]:
    login_str = form_data.username  # could be email also
    user = await authenticate_user(db, login_str, form_data.password)
    await create_tokens_and_set_auth_cookies_in_response(db, str(user.id), response)
    return {"message": "Logged in successfully"}


@router.get(
    "/me",
    dependencies=[CustomRateLimiterDepends20],
)
async def me_route(current_user: GetCurrentUserDep) -> UserSchema:
    return current_user


@router.post("/register", dependencies=[CustomRateLimiterDepends10])
async def register_route(
    user: UserCreateSchema,
    background_tasks: BackgroundTasks,
    db: GetDbSessionDep,
) -> dict[str, str]:
    user_crud = UserCRUD(db)
    db_user_by_email = await user_crud.get_by_email(user.email)
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user_by_username = await user_crud.get_by_username(user.username)
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already registered")
    created_user = await user_crud.create(user)
    token_for_email = TokenForEmail(
        is_for_password_reset=False, is_for_email_change=False
    )
    token = await token_for_email.generate_and_store(db, str(created_user.id))
    background_tasks.add_task(
        token_for_email.send_email, str(created_user.email), token
    )
    return {"message": "Confirmation email sent."}


@router.post(
    "/refresh",
    dependencies=[
        Depends(csrftoken_check),
        CustomRateLimiterDepends20,
    ],
)
async def refresh_token_route(
    response: Response,
    refresh_token_from_db: ValidateRefreshTokenFromCookieDep,
    db: GetDbSessionDep,
) -> dict[str, str]:
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await create_tokens_and_set_auth_cookies_in_response(
        db, str(refresh_token_from_db.user_id), response
    )
    return {"message": "Successfully refreshed tokens."}


@router.post(
    "/logout",
    dependencies=[
        Depends(csrftoken_check),
        Depends(get_current_user),
        CustomRateLimiterDepends10,
    ],
)
async def logout_route(
    response: Response,
    refresh_token_from_db: ValidateRefreshTokenFromCookieDep,
    db: GetDbSessionDep,
) -> dict[str, str]:
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await clear_auth_cookies_in_response(response)
    return {"message": "Successfully logged out"}


@router.post("/confirm-email", dependencies=[CustomRateLimiterDepends5])
async def confirm_email_route(
    data: TokenForEmailDep, db: GetDbSessionDep
) -> dict[str, str]:
    token_id, user_id = data["id"], data["user_id"]
    await TokenForEmailCRUD(db, is_for_password_reset=False).set_is_used_true(token_id)
    await UserCRUD(db).set_is_email_confirmed_and_is_active_true(user_id)
    return {"message": "Email was confirmed successfully."}


@router.post(
    "/resend-email-confirmation",
    dependencies=[CustomRateLimiterDepends10],
)
async def resend_confirmation_email_route(
    email: EmailStrEmbeddedDep,
    background_tasks: BackgroundTasks,
    db: GetDbSessionDep,
) -> dict[str, str]:
    user = await UserCRUD(db).get_by_email(email)
    if user and not user.is_email_confirmed:
        await TokenForEmailCRUD(
            db, is_for_password_reset=False
        ).set_is_used_true_on_all_tokens(str(user.id))
        token_for_email = TokenForEmail(
            is_for_password_reset=False, is_for_email_change=False
        )
        token = await token_for_email.generate_and_store(db, str(user.id))
        background_tasks.add_task(token_for_email.send_email, str(user.email), token)

    return {
        "message": "If an account with that email exists, a confirmation email has been sent."
    }


@router.post(
    "/request-password-reset",
    dependencies=[CustomRateLimiterDepends10],
)
async def request_password_reset(
    email: EmailStrEmbeddedDep,
    background_tasks: BackgroundTasks,
    db: GetDbSessionDep,
) -> dict[str, str]:
    user = await UserCRUD(db).get_by_email(email)
    if user and user.is_email_confirmed:
        token_for_email = TokenForEmail(is_for_password_reset=True)
        token = await token_for_email.generate_and_store(db, str(user.id))
        background_tasks.add_task(token_for_email.send_email, str(user.email), token)

    return {
        "message": "If an email address is associated with an account, a password reset link has been sent."
    }


@router.post("/reset-password", dependencies=[CustomRateLimiterDepends10])
async def reset_password_route(
    data: TokenForEmailPassResetDep,
    request_data: UserNewPasswordSchema,
    db: GetDbSessionDep,
) -> dict[str, str]:
    new_password = request_data.password
    token_id, user_id = data["id"], data["user_id"]
    await TokenForEmailCRUD(db, is_for_password_reset=True).set_is_used_true(token_id)
    await UserCRUD(db).update_password(new_password, user_id)
    return {"message": "Password was successfully reset."}


@router.post(
    "/archive-account",
    dependencies=[
        Depends(csrftoken_check),
        CustomRateLimiterDepends5,
    ],
)
async def archive_account_route(
    response: Response,
    current_user: VerifyPasswordForImportantChangesDep,
    refresh_token_from_db: ValidateRefreshTokenFromCookieDep,
    db: GetDbSessionDep,
) -> dict[str, str]:
    await UserCRUD(db).set_is_active_false(str(current_user.id))
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await clear_auth_cookies_in_response(response)
    return {"message": "Successfully archived"}


@router.post(
    "/request-email-change",
    dependencies=[
        Depends(csrftoken_check),
        CustomRateLimiterDepends10,
    ],
)
async def request_change_email_route(
    new_email: EmailStrEmbeddedDep,
    current_user: VerifyPasswordForImportantChangesDep,
    db: GetDbSessionDep,
    background_tasks: BackgroundTasks,
) -> dict[str, str]:
    db_user_by_email = await UserCRUD(db).get_by_email(new_email)
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    token_for_email = TokenForEmail(
        is_for_password_reset=False, is_for_email_change=True
    )
    token = await token_for_email.generate_and_store(
        db, str(current_user.id), new_email
    )
    background_tasks.add_task(token_for_email.send_email, new_email, token)
    return {
        "message": "Confirmation email sent. Please check your new email to confirm the email change."
    }


@router.post(
    "/confirm-email-change",
    dependencies=[CustomRateLimiterDepends10],
)
async def confirm_email_change_route(
    data: TokenForEmailDep, db: GetDbSessionDep
) -> dict[str, str]:
    token_id, user_id, extra_data = (data["id"], data["user_id"], data["extra_data"])
    await TokenForEmailCRUD(db, is_for_password_reset=False).set_is_used_true(token_id)
    await UserCRUD(db).update_email(extra_data["new_email"], user_id)
    return {"message": "Email was confirmed successfully."}


@router.post(
    "/change-password",
    dependencies=[
        Depends(csrftoken_check),
        CustomRateLimiterDepends5,
    ],
)
async def change_password_route(
    request_data: UserNewPasswordSchema,
    response: Response,
    current_user: VerifyPasswordForImportantChangesDep,
    refresh_token_from_db: ValidateRefreshTokenFromCookieDep,
    db: GetDbSessionDep,
) -> dict[str, str]:
    new_password = request_data.password
    await UserCRUD(db).update_password(new_password, str(current_user.id))
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await clear_auth_cookies_in_response(response)
    return {"message": "Password was successfully changed."}


@router.post(
    "/change-username",
    dependencies=[
        Depends(csrftoken_check),
        CustomRateLimiterDepends5,
    ],
)
async def change_username_route(
    request_data: UserNewUsernameSchema,
    response: Response,
    current_user: VerifyPasswordForImportantChangesDep,
    refresh_token_from_db: ValidateRefreshTokenFromCookieDep,
    db: GetDbSessionDep,
) -> dict[str, str]:
    new_username = request_data.username
    user_crud = UserCRUD(db)
    db_user_by_username = await user_crud.get_by_username(new_username)
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already registered")
    await UserCRUD(db).update_username(new_username, str(current_user.id))
    await RefreshTokenCRUD(db).set_revoke_status_to_true(str(refresh_token_from_db.id))
    await clear_auth_cookies_in_response(response)
    return {"message": "Username was successfully changed."}
