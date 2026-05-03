from __future__ import annotations

import asyncio

from sqlalchemy import select

from fastapi_rebac.db.adapters import create_sqlalchemy_user_db, create_user_manager
from fastapi_rebac.managers.user_manager import ReBACUserManager
from fastapi_rebac.models import User

from .config import settings
from .db import async_session_maker
from .main import rebac


async def main() -> None:
    async with async_session_maker() as session:
        await rebac.ensure_auth_tables(session, include_hidden=True)

        result = await session.execute(
            select(User).where(User.email == settings.first_superuser_email)
        )
        user = result.scalar_one_or_none()
        if user is not None:
            user.is_active = True
            user.is_staff = True
            user.is_superuser = True
            user.is_verified = True
            await session.commit()
            print(f"Superuser already exists and was updated: {user.email}")
            return

        user_db = create_sqlalchemy_user_db(session, User)
        manager = create_user_manager(ReBACUserManager, user_db)
        payload = await manager.admin_prepare_create_dict(
            email=settings.first_superuser_email,
            password=settings.first_superuser_password,
            is_active=True,
            is_superuser=True,
            is_staff=True,
            is_verified=True,
            extra={
                "username": settings.first_superuser_username,
                "first_name": "Admin",
                "last_name": "User",
            },
        )
        user = User(**payload)
        session.add(user)
        await session.commit()
        print(f"Created superuser: {user.email}")


if __name__ == "__main__":
    asyncio.run(main())
