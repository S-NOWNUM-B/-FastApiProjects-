from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.staticfiles import StaticFiles
from sqlmodel import select, Session
from models import User, UserCreate, UserLogin, UserRead
from database import create_db_and_tables, get_async_session_factory, engine
from auth import get_password_hash, verify_password, create_access_token, get_current_user, require_role, get_user_by_username
from routers import notes
from routers.tasks import send_mock_email
from routers import websocket
from prometheus_fastapi_instrumentator import Instrumentator
from middleware import LoggingMiddleware, RateLimiterMiddleware
from logger import logger
from redis.asyncio import Redis
from config import settings
from typing import AsyncGenerator

app = FastAPI(
    title="FastAPI Notes API",
    description="API для управления заметками с аутентификацией и авторизацией",
    version="1.0.0",
    contact={
        "name": "API Support",
        "email": "support@example.com"
    },
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(LoggingMiddleware)

redis = Redis.from_url(settings.REDIS_URL)
app.add_middleware(RateLimiterMiddleware, redis=redis)

app.include_router(notes.router)
app.include_router(websocket.router)
app.mount("/static", StaticFiles(directory="static"), name="static")

Instrumentator().instrument(app).expose(app)

async_session_factory = get_async_session_factory()

async def get_session() -> AsyncGenerator[Session, None]:
    async with async_session_factory() as session:
        yield session

async def create_admin():
    async with async_session_factory() as session:
        statement = select(User).where(User.username == "admin")
        result = await session.exec(statement)
        admin = result.scalar_one_or_none()
        if not admin:
            admin_user = User(
                username="admin",
                hashed_password=get_password_hash("adminpass"),
                role="admin"
            )
            session.add(admin_user)
            await session.commit()
            logger.info("Admin user created successfully")

app.add_event_handler("startup", create_db_and_tables)
app.add_event_handler("startup", create_admin)
app.add_event_handler("startup", lambda: logger.info("Application started"))

async def shutdown_event():
    await redis.aclose()
    logger.info("Application shutdown")

@app.get(
    "/health",
    tags=["System"],
    summary="Проверка работоспособности сервиса",
    description="Эндпоинт для проверки доступности сервиса и состояния базы данных",
    responses={
        200: {
            "description": "Сервис работает нормально",
            "content": {
                "application/json": {
                    "example": {"status": "healthy"}
                }
            }
        },
        503: {
            "description": "Сервис недоступен",
            "content": {
                "application/json": {
                    "example": {"detail": "Service unavailable"}
                }
            }
        }
    }
)
async def health_check(session: Session = Depends(get_session)):
    try:
        await session.exec("SELECT 1")
        return {"status": "healthy"}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=503, detail="Service unavailable")

@app.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="Регистрация нового пользователя",
    description="Создает нового пользователя в системе. Требует уникальное имя пользователя и пароль.",
    responses={
        201: {
            "description": "Пользователь успешно зарегистрирован",
            "model": UserRead
        },
        400: {
            "description": "Имя пользователя уже занято",
            "content": {
                "application/json": {
                    "example": {"detail": "Username already registered"}
                }
            }
        }
    }
)
async def register(user: UserCreate, session: Session = Depends(get_session)):
    existing_user = await get_user_by_username(session, user.username)
    if existing_user:
        logger.warning(f"Registration attempt with existing username: {user.username}")
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password)
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)
    logger.info(f"New user registered: {user.username}")
    return UserRead(id=new_user.id, username=new_user.username, role=new_user.role)

@app.post(
    "/login",
    tags=["Authentication"],
    summary="Аутентификация пользователя",
    description="Аутентифицирует пользователя и возвращает JWT токен",
    responses={
        200: {
            "description": "Успешная аутентификация",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer"
                    }
                }
            }
        },
        401: {
            "description": "Неверные учетные данные",
            "content": {
                "application/json": {
                    "example": {"detail": "Incorrect username or password"}
                }
            }
        }
    }
)
async def login(user: UserLogin, session: Session = Depends(get_session)):
    existing_user = await get_user_by_username(session, user.username)
    if not existing_user or not verify_password(user.password, existing_user.hashed_password):
        logger.warning(f"Failed login attempt for user: {user.username}")
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": existing_user.username})
    logger.info(f"User logged in successfully: {user.username}")
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get(
    "/users/me",
    response_model=UserRead,
    tags=["Users"],
    summary="Получить информацию о текущем пользователе",
    description="Возвращает информацию о текущем аутентифицированном пользователе",
    responses={
        200: {
            "description": "Информация о пользователе успешно получена",
            "model": UserRead
        },
        401: {
            "description": "Не аутентифицирован",
            "content": {
                "application/json": {
                    "example": {"detail": "Not authenticated"}
                }
            }
        }
    }
)
async def read_users_me(current_user: User = Depends(get_current_user)):
    logger.info(f"User profile accessed: {current_user.username}")
    return UserRead(id=current_user.id, username=current_user.username, role=current_user.role)

@app.get(
    "/admin/users",
    tags=["Admin"],
    summary="Получить список всех пользователей",
    description="Возвращает список всех пользователей в системе. Требует права администратора.",
    responses={
        200: {
            "description": "Список пользователей успешно получен",
            "content": {
                "application/json": {
                    "example": [
                        {"id": 1, "username": "user1", "role": "user"},
                        {"id": 2, "username": "admin", "role": "admin"}
                    ]
                }
            }
        },
        401: {
            "description": "Не аутентифицирован",
            "content": {
                "application/json": {
                    "example": {"detail": "Not authenticated"}
                }
            }
        },
        403: {
            "description": "Нет прав доступа",
            "content": {
                "application/json": {
                    "example": {"detail": "Not enough permissions"}
                }
            }
        }
    }
)
async def get_all_users(current_user: User = Depends(require_role("admin")), session: Session = Depends(get_session)):
    statement = select(User)
    result = await session.exec(statement)
    users = result.scalars().all()
    logger.info(f"Admin {current_user.username} accessed user list")
    return [UserRead(id=u.id, username=u.username, role=u.role) for u in users]

@app.post(
    "/trigger-task",
    tags=["Tasks"],
    summary="Запустить фоновую задачу",
    description="Запускает фоновую задачу отправки email для текущего пользователя",
    responses={
        200: {
            "description": "Задача успешно запущена",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Task started",
                    }
                }
            }
        },
        401: {
            "description": "Не аутентифицирован",
            "content": {
                "application/json": {
                    "example": {"detail": "Not authenticated"}
                }
            }
        }
    }
)
async def trigger_task(current_user: User = Depends(get_current_user)):
    send_mock_email.delay(current_user.username)
    logger.info(f"Task triggered by user: {current_user.username}")
    return {"message": "Task started"}

app.add_event_handler("shutdown", shutdown_event)