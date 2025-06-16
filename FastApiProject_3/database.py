from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

DATABASE_URL = "postgresql+asyncpg://postgres:123@localhost:5432/notesdb"
engine = create_async_engine(DATABASE_URL, echo=True, future=True)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

def create_db_and_tables():
    sync_engine = create_engine("postgresql+psycopg2://postgres:123@localhost:5432/notesdb")
    SQLModel.metadata.create_all(sync_engine)