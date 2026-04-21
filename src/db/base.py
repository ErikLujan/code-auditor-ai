"""
Base declarativa y mixins reutilizables para modelos SQLAlchemy.

Define la clase Base de la que heredan todos los modelos,
y mixins comunes (timestamps, UUID primary key) para evitar
repetición entre modelos (DRY).
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    Clase base declarativa para todos los modelos ORM.

    Todos los modelos del proyecto deben heredar de esta clase
    para ser reconocidos por Alembic y SQLAlchemy.
    """


class UUIDPrimaryKeyMixin:
    """
    Mixin que agrega un UUID v4 como primary key.

    Genera el UUID en Python (no en DB) para garantizar
    disponibilidad del ID antes del flush.
    """

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )


class TimestampMixin:
    """
    Mixin que agrega campos de auditoría de tiempo.

    Attributes:
        created_at: Timestamp de creación, seteado automáticamente.
        updated_at: Timestamp de última modificación, actualizado en cada UPDATE.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )