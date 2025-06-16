from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, inspect, text

DATABASE_URL = "postgresql+asyncpg://postgres:123@localhost:5432/notesdb"
engine = create_async_engine(DATABASE_URL, echo=True, future=True)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

def create_db_and_tables():
    sync_engine = create_engine("postgresql+psycopg2://postgres:123@localhost:5432/notesdb")
    SQLModel.metadata.create_all(sync_engine)
    inspector = inspect(sync_engine)
    columns = [col['name'] for col in inspector.get_columns('note')]
    if 'owner_id' not in columns:
        with sync_engine.connect() as conn:
            conn.execute(text('ALTER TABLE note ADD COLUMN owner_id INTEGER REFERENCES "user"(id);'))
            conn.commit()