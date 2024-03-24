import asyncio
import secrets

from passlib.context import CryptContext  # type: ignore

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def verify_password(plain_password, hashed_password) -> bool:
    return await asyncio.to_thread(pwd_context.verify, plain_password, hashed_password)


async def get_password_hash(password) -> str:
    return await asyncio.to_thread(pwd_context.hash, password)


async def generate_csrf_token() -> str:
    return secrets.token_hex(16)
