import re
from pydantic import BaseModel, ConfigDict, EmailStr, validator, Field
from uuid import UUID
from datetime import datetime

from core.security import check_password
from core.settings import settings


class PasswordMixin(BaseModel):
    @validator("password", check_fields=False)
    def validate_password(cls, password):
        return check_password(password)


class UsernameMixin(BaseModel):
    @validator("username", check_fields=False)
    def validate_username(cls, username):
        max_length = settings.MAX_USERNAME_LENGTH
        if len(username) > max_length:
            raise ValueError(
                f"Username must be no more than {max_length} characters long."
            )

        if not re.match("^[a-zA-Z0-9._]+$", username):
            raise ValueError(
                "Username must contain only letters, numbers, dots, and underscores."
            )

        return username


class NameMixin(BaseModel):

    @validator("first_name", check_fields=False)
    def validate_first_name(cls, value):
        value = value.strip() if value is not None else value
        if value is not None and not value:
            raise ValueError("First name cannot be empty or just whitespace.")
        return value

    @validator("last_name", check_fields=False)
    def validate_last_name(cls, value):
        value = value.strip() if value is not None else value
        if value is not None and not value:
            raise ValueError("Last name cannot be empty or just whitespace.")
        return value


class UserBaseSchema(BaseModel):
    email: EmailStr
    username: str


class UserCreateSchema(UsernameMixin, PasswordMixin, UserBaseSchema):
    password: str


class UserUpdateSchema(NameMixin, BaseModel):
    first_name: str | None = Field(..., max_length=50)
    last_name: str | None = Field(..., max_length=50)


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
