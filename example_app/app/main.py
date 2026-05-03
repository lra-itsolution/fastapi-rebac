from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, status
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_rebac import Action, FastAPIReBAC, SuspiciousActivityConfig
from fastapi_rebac.models import User
from fastapi_rebac.schemas import UserCreate, UserRead, UserUpdate

from .auth import auth_backend, cookie_auth_backend, get_user_manager
from .config import settings
from .db import async_session_maker
from .db import get_async_session as raw_get_async_session
from .models import Note
from .schemas import NoteCreate, NoteRead, NoteUpdate

rebac = FastAPIReBAC(
    get_user_manager,
    [auth_backend, cookie_auth_backend],
    get_async_session=raw_get_async_session,
    user_model=User,
    csrf_secret=settings.csrf_secret,
    csrf_cookie_secure=settings.cookie_secure,
    audit_enabled=True,
    suspicious_activity_config=SuspiciousActivityConfig(
        enabled=settings.suspicious_activity_enabled,
        rules_enabled=settings.suspicious_activity_rules_enabled,
        pyod_enabled=settings.suspicious_activity_pyod_enabled,
        window_minutes=settings.suspicious_activity_window_minutes,
        pyod_min_rows=settings.suspicious_activity_pyod_min_rows,
        min_events_for_pyod=settings.suspicious_activity_min_events_for_pyod,
        pyod_contamination=settings.suspicious_activity_pyod_contamination,
        many_denied_threshold=settings.suspicious_activity_many_denied_threshold,
        bulk_read_threshold=settings.suspicious_activity_bulk_read_threshold,
        many_deletes_threshold=settings.suspicious_activity_many_deletes_threshold,
        many_unique_objects_threshold=settings.suspicious_activity_many_unique_objects_threshold,
        many_unique_ips_threshold=settings.suspicious_activity_many_unique_ips_threshold,
        night_start_hour=settings.suspicious_activity_night_start_hour,
        night_end_hour=settings.suspicious_activity_night_end_hour,
    ),
)

rebac.register_admin_model(
    Note,
    title="Notes",
    user_ref_attr=Note.created_by_id,
    list_display=("id", "title", "created_by_id", "created_at"),
    readonly_fields={"created_at", "updated_at"},
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Tables must already exist. Run Alembic migrations before starting the app.
    async with async_session_maker() as session:
        await rebac.ensure_auth_tables(session, include_hidden=True)
    yield


app = FastAPI(title="fastapi-rebac example", lifespan=lifespan)

app.include_router(rebac.get_auth_router("jwt"), prefix="/auth/jwt", tags=["auth"])
app.include_router(rebac.get_register_router(UserRead, UserCreate), prefix="/auth", tags=["auth"])
app.include_router(rebac.get_users_router(UserRead, UserUpdate), prefix="/users", tags=["users"])
rebac.mount_admin(app, prefix="/admin")


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/notes",
    response_model=NoteRead,
    status_code=status.HTTP_201_CREATED,
    tags=["notes"],
)
async def create_note(
    payload: NoteCreate,
    user: User = Depends(rebac.require(Action.CREATE, Note)),
    session: AsyncSession = Depends(rebac.session_dependency),
) -> Note:
    note = Note(
        title=payload.title,
        body=payload.body,
        created_by_id=user.id,
    )
    session.add(note)
    await session.commit()
    await session.refresh(note)
    return note


@app.get("/notes", response_model=list[NoteRead], tags=["notes"])
async def list_notes(
    stmt: Any = Depends(rebac.accessible_select(Note.created_by_id)),
    session: AsyncSession = Depends(rebac.session_dependency),
) -> list[Note]:
    result = await session.execute(stmt.order_by(Note.created_at.desc()))
    return list(result.scalars().all())


@app.get("/notes/{note_id}", response_model=NoteRead, tags=["notes"])
async def get_note(
    note: Note = Depends(
        rebac.require_object(Action.READ, Note.created_by_id, object_id_param="note_id")
    ),
) -> Note:
    return note


@app.patch("/notes/{note_id}", response_model=NoteRead, tags=["notes"])
async def update_note(
    payload: NoteUpdate,
    note: Note = Depends(
        rebac.require_object(Action.UPDATE, Note.created_by_id, object_id_param="note_id")
    ),
    session: AsyncSession = Depends(rebac.session_dependency),
) -> Note:
    if payload.title is not None:
        note.title = payload.title
    if payload.body is not None:
        note.body = payload.body
    await session.commit()
    await session.refresh(note)
    return note


@app.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["notes"])
async def delete_note(
    note: Note = Depends(
        rebac.require_object(Action.DELETE, Note.created_by_id, object_id_param="note_id")
    ),
    session: AsyncSession = Depends(rebac.session_dependency),
) -> None:
    await session.delete(note)
    await session.commit()
