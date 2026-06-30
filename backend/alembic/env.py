from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from src.db.engine import get_sync_url
from src.db.models import Base

# Domain model modules that define tables on the shared Base but live outside
# db/models.py must be imported here so their tables register on Base.metadata
# before autogenerate runs — otherwise autogen sees them as absent and emits
# spurious DROP ops for tables the migrations already created.
import src.compliance.models  # noqa: E402,F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = get_sync_url()
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_sync_url()
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
