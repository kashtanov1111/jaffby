import __init__  # type: ignore

import asyncio
from datetime import datetime, timezone, timedelta

from sqlalchemy import delete
from sqlalchemy.sql.expression import and_


from core.database import SessionLocal
from models.users import User


async def delete_expired_or_used_tokens() -> None:
    async with SessionLocal() as db:
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=25)
        delete_stmt = delete(User).where(
            and_(User.created_at < time_threshold, User.is_email_confirmed == False)
        )
        await db.execute(delete_stmt)
        await db.commit()


if __name__ == "__main__":
    asyncio.run(delete_expired_or_used_tokens())
