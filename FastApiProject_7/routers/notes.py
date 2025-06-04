from fastapi import APIRouter, HTTPException, status, Depends, Path
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from ..models import Note, NoteCreate, NoteUpdate, NoteOut
from ..database import async_session
from ..auth import get_current_user
from ..models import User

router = APIRouter(prefix="/notes", tags=["notes"])

@router.post("/", response_model=NoteOut)
async def create_note(
    note: NoteCreate,
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        new_note = Note(text=note.text, owner_id=current_user.id)
        session.add(new_note)
        await session.commit()
        await session.refresh(new_note)
        return new_note

@router.get("/", response_model=list[NoteOut])
async def read_notes(current_user: User = Depends(get_current_user)):
    async with async_session() as session:
        statement = select(Note).where(Note.owner_id == current_user.id)
        result = await session.execute(statement)
        notes = result.scalars().all()
        return notes

@router.get("/{note_id}", response_model=NoteOut)
async def read_note(
    note_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        note = await session.get(Note, note_id)
        if not note or note.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")
        return note

@router.put("/{note_id}", response_model=NoteOut)
async def update_note(
    note_id: int,
    note_update: NoteUpdate,
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        note = await session.get(Note, note_id)
        if not note or note.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")

        if note_update.text is not None:
            note.text = note_update.text

        session.add(note)
        await session.commit()
        await session.refresh(note)
        return note

@router.delete("/{note_id}")
async def delete_note(
    note_id: int,
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        note = await session.get(Note, note_id)
        if not note or note.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")

        await session.delete(note)
        await session.commit()
        return {"detail": "Note deleted successfully"}