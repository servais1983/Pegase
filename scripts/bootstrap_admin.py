"""Create the first admin user from environment variables.

Usage:
    PEGASE_ADMIN_USERNAME=admin \
    PEGASE_ADMIN_EMAIL=admin@example.org \
    PEGASE_ADMIN_PASSWORD=... \
    python -m scripts.bootstrap_admin
"""

from __future__ import annotations

import os
import sys

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from pegase.core.auth import hash_password
from pegase.core.config import get_settings
from pegase.db.models import User


def main() -> int:
    username = os.environ.get("PEGASE_ADMIN_USERNAME")
    email = os.environ.get("PEGASE_ADMIN_EMAIL")
    password = os.environ.get("PEGASE_ADMIN_PASSWORD")
    if not (username and email and password):
        print(
            "PEGASE_ADMIN_USERNAME, PEGASE_ADMIN_EMAIL and "
            "PEGASE_ADMIN_PASSWORD must all be set.",
            file=sys.stderr,
        )
        return 1
    settings = get_settings()
    engine = create_engine(settings.database_sync_url, future=True)
    Session = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with Session() as db:
        if db.scalar(select(User).where(User.username == username)):
            print(f"user '{username}' already exists.")
            return 0
        db.add(
            User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                role="admin",
            )
        )
        db.commit()
    print(f"created admin user '{username}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
