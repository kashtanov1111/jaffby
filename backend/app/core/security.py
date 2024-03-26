import re
import asyncio
import secrets
from pydantic import EmailStr

from passlib.context import CryptContext  # type: ignore

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def verify_password(plain_password, hashed_password) -> bool:
    return await asyncio.to_thread(pwd_context.verify, plain_password, hashed_password)


async def get_password_hash(password) -> str:
    return await asyncio.to_thread(pwd_context.hash, password)


async def generate_csrf_token() -> str:
    return secrets.token_hex(16)


def check_password(password: str) -> str:
    min_length = 8
    if len(password) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters long.")
    if not re.search("[a-z]", password):
        raise ValueError("Password must include lowercase letters.")
    if not re.search("[A-Z]", password):
        raise ValueError("Password must include uppercase letters.")
    if not re.search("[0-9]", password):
        raise ValueError("Password must include digits.")
    if not re.search('[!@#$%^&*(),.?":{}|<>]', password):
        raise ValueError(
            'Password must include special characters (!@#$%^&*(),.?":{}|<>).'
        )
    return password
