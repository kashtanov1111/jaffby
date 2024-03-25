import __init__  # type: ignore

import asyncio
from datetime import datetime

from sqlalchemy import delete

from core.database import SessionLocal
from models.email_confirmation_tokens import EmailConfirmationToken


async def delete_expired_or_used_tokens() -> None:
    async with SessionLocal() as db:
        current_time = datetime.now()
        delete_stmt = delete(EmailConfirmationToken).where(
            (EmailConfirmationToken.expires_at < current_time)
            | (EmailConfirmationToken.is_used == True)
        )
        await db.execute(delete_stmt)
        await db.commit()


if __name__ == "__main__":
    asyncio.run(delete_expired_or_used_tokens())
