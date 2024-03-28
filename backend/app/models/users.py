import uuid

from sqlalchemy import Column, String, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import DateTime, func

from core.settings import settings
from core.database import Base  # type: ignore


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(length=254), unique=True, nullable=False)
    username = Column(
        String(length=settings.MAX_USERNAME_LENGTH), unique=True, nullable=False
    )
    hashed_password = Column(String(length=60), nullable=False)
    is_active = Column(Boolean, default=False)
    is_email_confirmed = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    first_name = Column(String(length=50), nullable=True)
    last_name = Column(String(length=50), nullable=True)
    created_at = Column(DateTime, default=func.now())

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete, delete-orphan"
    )
    email_confirmation_tokens = relationship(
        "EmailConfirmationToken",
        back_populates="user",
        order_by="EmailConfirmationToken.created_at",
        cascade="all, delete, delete-orphan",
    )
    password_reset_tokens = relationship(
        "PasswordResetToken",
        back_populates="user",
        order_by="PasswordResetToken.created_at",
        cascade="all, delete, delete-orphan",
    )
