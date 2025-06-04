from fastapi import FastAPI, HTTPException, status
from sqlmodel import select
from models import User, UserCreate, UserLogin, UserRead
from database import engine, async_session, create_db_and_tables
from typing import List

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    create_db_and_tables()

@app.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    async with async_session() as session:
        statement = select(User).where(User.username == user.username)
        result = await session.execute(statement)
        existing_user = result.scalar_one_or_none()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")

        new_user = User(username=user.username, password=user.password)
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)
        return UserRead(id=new_user.id, username=new_user.username)

@app.post("/login")
async def login(user: UserLogin):
    async with async_session() as session:
        statement = select(User).where(User.username == user.username)
        result = await session.execute(statement)
        existing_user = result.scalar_one_or_none()
        if not existing_user or existing_user.password != user.password:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        return {"message": "Login successful", "username": existing_user.username}