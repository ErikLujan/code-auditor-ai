"""
Configuración de Alembic para migraciones async.

Soporta modo offline (genera SQL sin conectarse a DB)
y modo online (aplica migraciones con conexión activa).

Nota: statement_cache_size=0 es requerido cuando se usa
PgBouncer en modo transaction (ej: Supabase Transaction Pooler).
Se fuerza schema 'public' para evitar conflictos con schemas
internos de Supabase (auth, storage, etc).
"""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import create_async_engine

from src.db.base import Base
from src.db.models import Analysis, Finding, Repository, User

load_dotenv()

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
target_metadata.schema = None

DATABASE_URL = os.environ["DATABASE_URL"]


def run_migrations_offline() -> None:
    """
    Ejecuta migraciones en modo offline.

    Genera SQL puro sin conectarse a la base de datos.
    """
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        version_table_schema="public",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """
    Ejecuta migraciones en modo online con engine async.

    Fuerza search_path a 'public' para garantizar que todas
    las tablas se creen en el schema correcto de Supabase.
    """
    connectable = create_async_engine(
        DATABASE_URL,
        poolclass=pool.NullPool,
        connect_args={"statement_cache_size": 0},
    )

    async with connectable.connect() as connection:
        await connection.execute(text("SET search_path TO public"))

        await connection.run_sync(
            lambda sync_conn: context.configure(
                connection=sync_conn,
                target_metadata=target_metadata,
                compare_type=True,
                version_table_schema="public",
            )
        )
        await connection.run_sync(lambda _: context.run_migrations())

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())