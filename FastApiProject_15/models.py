from sqlmodel import SQLModel, Field, Relationship
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: str = Field(default='user')
    notes: list["Note"] = Relationship(back_populates="owner")

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserRead(BaseModel):
    id: int
    username: str
    role: str

class Note(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    text: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    owner_id: int = Field(foreign_key="user.id")
    owner: Optional["User"] = Relationship(back_populates="notes")

class NoteCreate(BaseModel):
    text: str

class NoteUpdate(BaseModel):
    text: Optional[str] = None

class NoteOut(BaseModel):
    id: int
    text: str
    created_at: datetime
    owner_id: int