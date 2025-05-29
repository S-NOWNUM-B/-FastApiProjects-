from fastapi import FastAPI
from sqlmodel import SQLModel, Field, select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from pydantic import BaseModel

app = FastAPI()

class Note(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    text: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class NoteCreate(BaseModel):
    text: str

class NoteOut(BaseModel):
    id: int
    text: str
    created_at: datetime

DATABASE_URL = "postgresql+asyncpg://postgres:123@localhost:5432/notesdb"

engine = create_async_engine(DATABASE_URL, echo=True, future=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

@app.post("/notes", response_model=NoteOut)
async def create_note(note_create: NoteCreate):
    async with async_session() as session:
        note = Note(text=note_create.text)
        session.add(note)
        await session.commit()
        await session.refresh(note)
        return note

@app.get("/notes", response_model=list[NoteOut])
async def read_notes():
    async with async_session() as session:
        result = await session.execute(select(Note))
        notes = result.scalars().all()
        return notes