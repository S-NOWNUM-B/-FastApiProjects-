from fastapi import FastAPI
from sqlmodel import select
from models import Note, NoteCreate, NoteOut
from database import engine, async_session
from typing import List

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Note.metadata.create_all)

@app.post("/notes", response_model=NoteOut)
async def create_note(note_create: NoteCreate):
    async with async_session() as session:
        note = Note(text=note_create.text)
        session.add(note)
        await session.commit()
        await session.refresh(note)
        return note

@app.get("/notes", response_model=List[NoteOut])
async def read_notes():
    async with async_session() as session:
        result = await session.execute(select(Note))
        notes = result.scalars().all()
        return notes