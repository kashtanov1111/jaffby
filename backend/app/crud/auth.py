from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update

from models.refresh_tokens import RefreshToken
from schemas.auth import RefreshTokenCreateSchema


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
