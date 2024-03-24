import __init__  # type: ignore

import asyncio
from datetime import datetime

from sqlalchemy import delete

from core.database import SessionLocal
from models.refresh_tokens import RefreshToken


async def delete_expired_or_revoked_tokens() -> None:
    async with SessionLocal() as db:
        current_time = datetime.now()
        delete_stmt = delete(RefreshToken).where(
            (RefreshToken.expires_at < current_time) | (RefreshToken.revoked == True)
        )
        await db.execute(delete_stmt)
        await db.commit()


if __name__ == "__main__":
    asyncio.run(delete_expired_or_revoked_tokens())
