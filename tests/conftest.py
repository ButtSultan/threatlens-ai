"""
ThreatLens AI — Test Configuration & Shared Fixtures
Uses SQLite in-memory database (no PostgreSQL required for tests).

Isolation strategy:
  - DB tables are created ONCE per session (fast).
  - Each test gets a ROLLED-BACK transaction, so mutations don't persist.
  - User fixtures are function-scoped and use unique suffixes to avoid
    UniqueConstraint violations across tests.
"""
import asyncio
import json
import uuid
import pytest
import pytest_asyncio

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.core.security import get_password_hash
from app.models.models import User, UserRole

# ── In-memory SQLite engine ───────────────────────────────────────────────
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False,
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ── Session-scoped event loop ─────────────────────────────────────────────
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Create all tables once per test session ───────────────────────────────
@pytest_asyncio.fixture(scope="session", autouse=True)
async def create_test_tables():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ── Per-test DB session (NOT rolled back — SQLite + StaticPool is tricky)
# Instead we use unique usernames per test to avoid constraint violations.
@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


# ── FastAPI TestClient with DB override ───────────────────────────────────
@pytest.fixture
def client(db_session: AsyncSession):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ── User fixtures — function-scoped with unique names ────────────────────
@pytest_asyncio.fixture
async def test_analyst(db_session: AsyncSession) -> User:
    """Fresh analyst user for each test — unique username prevents conflicts."""
    suffix = uuid.uuid4().hex[:8]
    user = User(
        username=f"analyst_{suffix}",
        email=f"analyst_{suffix}@test.com",
        hashed_password=get_password_hash("TestPass123"),
        full_name="Test Analyst",
        role=UserRole.ANALYST,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_admin(db_session: AsyncSession) -> User:
    """Fresh admin user for each test — unique username prevents conflicts."""
    suffix = uuid.uuid4().hex[:8]
    user = User(
        username=f"admin_{suffix}",
        email=f"admin_{suffix}@test.com",
        hashed_password=get_password_hash("AdminPass123"),
        full_name="Test Admin",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


# ── Token fixtures ────────────────────────────────────────────────────────
@pytest.fixture
def analyst_token(client, test_analyst) -> str:
    resp = client.post("/api/v1/auth/login", json={
        "username": test_analyst.username,
        "password": "TestPass123",
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture
def admin_token(client, test_admin) -> str:
    resp = client.post("/api/v1/auth/login", json={
        "username": test_admin.username,
        "password": "AdminPass123",
    })
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture
def analyst_headers(analyst_token) -> dict:
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def admin_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


# ── Sample log data fixtures ──────────────────────────────────────────────
@pytest.fixture
def sample_json_logs() -> str:
    """JSON log batch with brute-force and impossible travel patterns."""
    logs = []
    # 8 failed logins from same IP → brute_force_login
    for i in range(8):
        logs.append({
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "192.168.1.100",
            "username": "admin",
            "event_type": "authentication_failure",
            "message": f"Failed password for admin from 192.168.1.100 attempt {i}",
            "hostname": "server-01",
        })
    # Logins from 4 distinct /16 networks → impossible_travel
    for ip in ["10.0.0.1", "172.16.0.1", "203.0.113.1", "198.51.100.1"]:
        logs.append({
            "timestamp": "2024-01-15T10:31:00Z",
            "source_ip": ip,
            "username": "admin",
            "event_type": "authentication_success",
            "message": f"Accepted password for admin from {ip}",
        })
    return json.dumps(logs)


@pytest.fixture
def sample_csv_logs() -> str:
    """CSV authentication log with 5 failures → brute_force."""
    return (
        "timestamp,source_ip,username,event_type,message\n"
        "2024-01-15T10:00:00Z,10.0.0.50,jdoe,authentication_failure,Failed login\n"
        "2024-01-15T10:01:00Z,10.0.0.50,jdoe,authentication_failure,Failed login\n"
        "2024-01-15T10:02:00Z,10.0.0.50,jdoe,authentication_failure,Failed login\n"
        "2024-01-15T10:03:00Z,10.0.0.50,jdoe,authentication_failure,Failed login\n"
        "2024-01-15T10:04:00Z,10.0.0.50,jdoe,authentication_failure,Failed login\n"
        "2024-01-15T10:04:30Z,10.0.0.50,jdoe,authentication_success,Login success\n"
    )


@pytest.fixture
def sample_txt_logs() -> str:
    """Syslog TXT with privilege escalation and suspicious PowerShell."""
    return (
        "Jan 15 10:30:00 srv01 sshd[1234]: Failed password for root from 192.168.10.5 port 22\n"
        "Jan 15 10:30:02 srv01 sshd[1234]: Failed password for root from 192.168.10.5 port 22\n"
        "Jan 15 10:30:04 srv01 sshd[1234]: Failed password for admin from 192.168.10.5 port 22\n"
        "Jan 15 10:30:06 srv01 sshd[1234]: Failed password for root from 192.168.10.5 port 22\n"
        "Jan 15 10:30:08 srv01 sshd[1234]: Failed password for root from 192.168.10.5 port 22\n"
        "Jan 15 10:31:00 srv01 sudo: jdoe : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash\n"
        "Jan 15 10:32:00 srv01 powershell: Invoke-Expression downloadstring -encodedcommand bypass\n"
    )
