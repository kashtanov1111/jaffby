from core.database import SessionLocal


async def get_db_session():
    async with SessionLocal() as session:
        yield session
