import __init__  # type: ignore

import asyncio
from datetime import datetime

from sqlalchemy import delete

from core.database import SessionLocal
from models.confirmation_tokens import ConfirmationToken


async def delete_expired_or_used_tokens() -> None:
    async with SessionLocal() as db:
        current_time = datetime.now()
        delete_stmt = delete(ConfirmationToken).where(
            (ConfirmationToken.expires_at < current_time)
            | (ConfirmationToken.is_used == True)
        )
        await db.execute(delete_stmt)
        await db.commit()


if __name__ == "__main__":
    asyncio.run(delete_expired_or_used_tokens())
