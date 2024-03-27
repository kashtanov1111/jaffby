import re
from pydantic import BaseModel, ConfigDict, EmailStr, validator, Field
from uuid import UUID
from datetime import datetime

from core.security import check_password


class PasswordMixin(BaseModel):
    @validator("password", check_fields=False)
    def validate_password(cls, password):
        return check_password(password)


class UsernameMixin(BaseModel):
    @validator("username", check_fields=False)
    def validate_username(cls, username):
        max_length = 30
        if len(username) > max_length:
            raise ValueError(
                f"Username must be no more than {max_length} characters long."
            )

        if not re.match("^[a-zA-Z0-9._]+$", username):
            raise ValueError(
                "Username must contain only letters, numbers, dots, and underscores."
            )

        return username


class UserBaseSchema(BaseModel):
    email: EmailStr
    username: str


class UserCreateSchema(UsernameMixin, PasswordMixin, UserBaseSchema):
    password: str


class UserSchema(UserBaseSchema):
    id: UUID
    is_active: bool
    first_name: str | None
    last_name: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserNewPasswordSchema(PasswordMixin, BaseModel):
    password: str = Field(..., alias="new_password")


class UserNewUsernameSchema(UsernameMixin, BaseModel):
    username: str = Field(..., alias="new_username")
