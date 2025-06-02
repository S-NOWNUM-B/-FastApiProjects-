from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import SQLModel, Field, select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy import create_engine
from datetime import datetime, timedelta
from jose import JWTError, jwt
import asyncio

SECRET_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

DATABASE_URL = "postgresql+asyncpg://postgres:123@localhost:5432/notesdb"
engine = create_async_engine(DATABASE_URL, echo=True, future=True)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: str = Field(default='user')

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

def create_db_and_tables():
    sync_engine = create_engine("postgresql+psycopg2://postgres:123@localhost:5432/notesdb")
    SQLModel.metadata.create_all(sync_engine)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_user_by_username(session: AsyncSession, username: str):
    statement = select(User).where(User.username == username)
    result = await session.execute(statement)
    return result.scalar_one_or_none()

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    async with async_session() as session:
        user = await get_user_by_username(session, username)
        if user is None:
            raise credentials_exception
        return user

def require_role(required_role: str):
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted",
            )
        return current_user
    return role_checker

@app.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    async with async_session() as session:
        existing_user = await get_user_by_username(session, user.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")

        hashed_password = get_password_hash(user.password)
        new_user = User(username=user.username, hashed_password=hashed_password)
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)
        return UserRead(id=new_user.id, username=new_user.username, role=new_user.role)

@app.post("/login")
async def login(user: UserLogin):
    async with async_session() as session:
        existing_user = await get_user_by_username(session, user.username)
        if not existing_user or not verify_password(user.password, existing_user.hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        access_token = create_access_token(data={"sub": existing_user.username})
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }

@app.get("/users/me", response_model=UserRead)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return UserRead(id=current_user.id, username=current_user.username, role=current_user.role)

@app.get("/admin/users")
async def get_all_users(current_user: User = Depends(require_role("admin"))):
    async with async_session() as session:
        statement = select(User)
        result = await session.execute(statement)
        users = result.scalars().all()
        return [{"id": u.id, "username": u.username, "role": u.role} for u in users]

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

    async def create_admin():
        async with async_session() as session:
            statement = select(User).where(User.username == "admin")
            result = await session.execute(statement)
            admin = result.scalar_one_or_none()
            if not admin:
                admin_user = User(
                    username="admin",
                    hashed_password=get_password_hash("adminpass"),
                    role="admin"
                )
                session.add(admin_user)
                await session.commit()
                print("Admin user created with username='admin' and password='adminpass'")

        asyncio.create_task(create_admin())