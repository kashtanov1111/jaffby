from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update

from models.refresh_tokens import RefreshToken
from models.confirmation_tokens import ConfirmationToken
from schemas.auth import RefreshTokenCreateSchema, ConfirmationTokenCreate


async def get_refresh_token_by_id(
    db: AsyncSession, refresh_token_id: str
) -> RefreshToken | None:
    result = await db.execute(
        select(RefreshToken).filter(RefreshToken.id == refresh_token_id)
    )
    refresh_token = result.scalars().first()
    return refresh_token


async def set_revoke_status_to_true_refresh_token(
    db: AsyncSession, refresh_token_id: str
) -> None:
    update_refresh_token = (
        update(RefreshToken)
        .where(RefreshToken.id == refresh_token_id)
        .values(revoked=True)
    )
    await db.execute(update_refresh_token)
    await db.commit()


async def create_refresh_token(
    db: AsyncSession, refresh_token: RefreshTokenCreateSchema
) -> RefreshToken:
    db_refresh_token = RefreshToken(
        id=refresh_token.id,
        user_id=refresh_token.user_id,
        token=refresh_token.token,
        expires_at=refresh_token.expires_at,
    )
    db.add(db_refresh_token)
    await db.commit()
    await db.refresh(db_refresh_token)
    return db_refresh_token


async def create_confirmation_token(
    db: AsyncSession, confirmation_token: ConfirmationTokenCreate
) -> None:
    db_confirmation_token = ConfirmationToken(
        token=confirmation_token.token,
        user_id=confirmation_token.user_id,
        created_at=confirmation_token.created_at,
        expires_at=confirmation_token.expires_at,
    )
    db.add(db_confirmation_token)
    await db.commit()
    await db.refresh(db_confirmation_token)


async def get_confirmation_token_by_token(
    db: AsyncSession, token: str
) -> ConfirmationToken | None:
    result = await db.execute(
        select(ConfirmationToken).filter(ConfirmationToken.token == token)
    )
    confirmation_token = result.scalars().first()
    return confirmation_token


async def set_is_used_true_on_confirmation_token(
    db: AsyncSession, token_id: str
) -> None:
    update_confirmation_token = (
        update(ConfirmationToken)
        .where(ConfirmationToken.id == token_id)
        .values(is_used=True)
    )
    await db.execute(update_confirmation_token)
    await db.commit()
