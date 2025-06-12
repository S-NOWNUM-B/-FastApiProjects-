from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.staticfiles import StaticFiles
from sqlmodel import select
from models import User, UserCreate, UserLogin, UserRead
from database import create_db_and_tables, async_session
from auth import get_password_hash, verify_password, create_access_token, get_current_user, require_role, get_user_by_username
from routers import notes
from routers.tasks import send_mock_email
from routers import websocket

app = FastAPI()
app.include_router(notes.router)
app.include_router(websocket.router)
app.mount("/static", StaticFiles(directory="static"), name="static")

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

@app.on_event("startup")
async def on_startup():
    await create_db_and_tables()
    await create_admin()

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

@app.post("/trigger-task")
async def trigger_task(current_user: User = Depends(get_current_user)):
    task = send_mock_email.delay(current_user.username)
    return {
        "message": "Task started",
        "task_id": task.id
    }