import pytest
import pytest_asyncio
from httpx import AsyncClient
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel
from main import app
from database import async_session, engine
from models import User
from auth import get_password_hash, create_access_token
from asgi_lifespan import LifespanManager

@pytest_asyncio.fixture(scope="module")
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)

    async with async_session() as session:
        hashed_password = get_password_hash("testpass")
        test_user = User(username="testuser", hashed_password=hashed_password)
        session.add(test_user)
        await session.commit()

    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(base_url="http://test", transport=transport) as c:
            yield c

@pytest.mark.asyncio
async def test_register(client):
    res = await client.post("/register", json={"username": "newuser", "password": "newpass"})
    assert res.status_code == 201

    res_dup = await client.post("/register", json={"username": "newuser", "password": "newpass"})
    assert res_dup.status_code == 400

@pytest.mark.asyncio
async def test_login(client):
    res = await client.post("/login", json={"username": "testuser", "password": "testpass"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data

    res_fail = await client.post("/login", json={"username": "testuser", "password": "wrongpass"})
    assert res_fail.status_code == 401

@pytest.mark.asyncio
async def test_get_me(client):
    token = create_access_token({"sub": "testuser"})
    headers = {"Authorization": f"Bearer {token}"}

    res = await client.get("/users/me", headers=headers)
    assert res.status_code == 200
    assert res.json()["username"] == "testuser"

    res_no_token = await client.get("/users/me")
    assert res_no_token.status_code == 401

@pytest.mark.asyncio
async def test_notes_crud(client):
    token = create_access_token({"sub": "testuser"})
    headers = {"Authorization": f"Bearer {token}"}

    res_create = await client.post("/notes/", json={"text": "test note"}, headers=headers)
    assert res_create.status_code == 200
    note_id = res_create.json()["id"]

    res_all = await client.get("/notes/", headers=headers)
    assert res_all.status_code == 200
    assert any(note["id"] == note_id for note in res_all.json())

    res_del = await client.delete(f"/notes/{note_id}", headers=headers)
    assert res_del.status_code == 200

    res_del_fail = await client.delete(f"/notes/{note_id}", headers=headers)
    assert res_del_fail.status_code == 404
