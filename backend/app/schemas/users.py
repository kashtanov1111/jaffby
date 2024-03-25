import re
from pydantic import BaseModel, ConfigDict, EmailStr, validator
from uuid import UUID
from datetime import datetime

from core.security import check_password


class PasswordMixin(BaseModel):
    @validator("password", check_fields=False)
    def validate_password(cls, password):
        return check_password(password)


class UserBaseSchema(BaseModel):
    email: EmailStr
    username: str


class UserCreateSchema(PasswordMixin, UserBaseSchema):
    password: str


class UserSchema(UserBaseSchema):
    id: UUID
    is_active: bool
    first_name: str | None
    last_name: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserPasswordResetSchema(PasswordMixin, BaseModel):
    password: str
