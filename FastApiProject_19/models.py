from sqlmodel import SQLModel, Field, Relationship
from pydantic import BaseModel, Field as PydanticField
from typing import Optional
from datetime import datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None,
        primary_key=True,
        description="Уникальный идентификатор пользователя"
    )
    username: str = Field(
        index=True,
        unique=True,
        description="Уникальное имя пользователя для входа в систему"
    )
    hashed_password: str = Field(
        description="Хешированный пароль пользователя"
    )
    role: str = Field(
        default='user',
        description="Роль пользователя в системе (user/admin)"
    )
    notes: list["Note"] = Relationship(back_populates="owner")

class UserCreate(BaseModel):
    username: str = PydanticField(
        description="Имя пользователя для регистрации",
        example="john_doe",
        min_length=3,
        max_length=50
    )
    password: str = PydanticField(
        description="Пароль пользователя",
        example="strongpassword123",
        min_length=8
    )

class UserLogin(BaseModel):
    username: str = PydanticField(
        description="Имя пользователя для входа",
        example="john_doe"
    )
    password: str = PydanticField(
        description="Пароль пользователя",
        example="strongpassword123"
    )

class UserRead(BaseModel):
    id: int = PydanticField(
        description="Уникальный идентификатор пользователя",
        example=1
    )
    username: str = PydanticField(
        description="Имя пользователя",
        example="john_doe"
    )
    role: str = PydanticField(
        description="Роль пользователя в системе",
        example="user"
    )

class Note(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None,
        primary_key=True,
        description="Уникальный идентификатор заметки"
    )
    text: str = Field(
        description="Текст заметки"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Дата и время создания заметки"
    )
    owner_id: int = Field(
        foreign_key="user.id",
        description="ID владельца заметки"
    )
    owner: Optional["User"] = Relationship(back_populates="notes")
    is_completed: bool = Field(
        default=False,
        description="Статус выполнения заметки"
    )

class NoteCreate(BaseModel):
    text: str = PydanticField(
        description="Текст новой заметки",
        example="Купить молоко и хлеб",
        min_length=1,
        max_length=1000
    )

class NoteUpdate(BaseModel):
    text: Optional[str] = PydanticField(
        default=None,
        description="Новый текст заметки",
        example="Купить молоко, хлеб и яйца",
        min_length=1,
        max_length=1000
    )

class NoteOut(BaseModel):
    id: int = PydanticField(
        description="Уникальный идентификатор заметки",
        example=1
    )
    text: str = PydanticField(
        description="Текст заметки",
        example="Купить молоко и хлеб"
    )
    created_at: datetime = PydanticField(
        description="Дата и время создания заметки",
        example="2024-03-20T10:30:00"
    )
    owner_id: int = PydanticField(
        description="ID владельца заметки",
        example=1
    )