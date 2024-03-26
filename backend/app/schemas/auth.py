from pydantic import BaseModel, ConfigDict, Field
from typing import Dict, Any, Optional
from uuid import UUID
from datetime import datetime


class RefreshTokenBaseSchema(BaseModel):
    id: UUID
    user_id: UUID
    token: str
    expires_at: datetime


class RefreshTokenCreateSchema(RefreshTokenBaseSchema):
    pass


class RefreshTokenSchema(RefreshTokenBaseSchema):
    revoked: bool

    model_config = ConfigDict(from_attributes=True)


class TokenForEmailBaseSchema(BaseModel):
    token: str
    user_id: UUID
    created_at: datetime
    expires_at: datetime


class EmailConfirmationCreateSchema(TokenForEmailBaseSchema):
    is_for_change: bool
    extra_data: Optional[Dict[str, Any]] = Field(default=None)


class PasswordResetCreateSchema(TokenForEmailBaseSchema):
    pass
