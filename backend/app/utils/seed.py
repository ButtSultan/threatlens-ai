"""
ThreatLens AI — Database Seed Script
Creates the initial admin user and demo data on first deployment.

Usage:
    # Via Docker:
    docker compose exec backend python -m app.utils.seed

    # Locally:
    cd backend && python -m app.utils.seed
"""

import asyncio
import logging
import os
import sys

# Ensure the backend directory is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.security import get_password_hash
from app.models.models import Alert, AlertStatus, Incident, LogEntry, LogType, SeverityLevel, User, UserRole

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


# ── Default credentials (override via environment variables) ──────────────
ADMIN_USERNAME = os.getenv("SEED_ADMIN_USERNAME", "admin")
ADMIN_EMAIL    = os.getenv("SEED_ADMIN_EMAIL",    "admin@threatlens.local")
ADMIN_PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "ThreatLens@Admin1")
ADMIN_FULLNAME = os.getenv("SEED_ADMIN_FULLNAME", "System Administrator")

DEMO_USERNAME = os.getenv("SEED_DEMO_USERNAME", "analyst")
DEMO_EMAIL    = os.getenv("SEED_DEMO_EMAIL",    "analyst@threatlens.local")
DEMO_PASSWORD = os.getenv("SEED_DEMO_PASSWORD", "ThreatLens@Demo1")


async def seed_database() -> None:
    """Run all seed operations."""
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with SessionLocal() as session:
        await _seed_admin_user(session)
        await _seed_demo_analyst(session)
        await _seed_sample_alert(session)
        await session.commit()

    await engine.dispose()
    logger.info("Database seeding complete.")


async def _seed_admin_user(session: AsyncSession) -> None:
    """Create the default admin user if it doesn't exist."""
    existing = await session.execute(
        select(User).where(User.username == ADMIN_USERNAME)
    )
    if existing.scalar_one_or_none():
        logger.info(f"Admin user '{ADMIN_USERNAME}' already exists — skipping.")
        return

    admin = User(
        username=ADMIN_USERNAME,
        email=ADMIN_EMAIL,
        hashed_password=get_password_hash(ADMIN_PASSWORD),
        full_name=ADMIN_FULLNAME,
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    session.add(admin)
    await session.flush()

    logger.info(f"✅ Admin user created:")
    logger.info(f"   Username : {ADMIN_USERNAME}")
    logger.info(f"   Email    : {ADMIN_EMAIL}")
    logger.info(f"   Password : {ADMIN_PASSWORD}")
    logger.info(f"   ⚠️  Change this password immediately after first login!")


async def _seed_demo_analyst(session: AsyncSession) -> None:
    """Create a demo analyst account for testing."""
    existing = await session.execute(
        select(User).where(User.username == DEMO_USERNAME)
    )
    if existing.scalar_one_or_none():
        logger.info(f"Demo analyst '{DEMO_USERNAME}' already exists — skipping.")
        return

    analyst = User(
        username=DEMO_USERNAME,
        email=DEMO_EMAIL,
        hashed_password=get_password_hash(DEMO_PASSWORD),
        full_name="Demo Analyst",
        role=UserRole.ANALYST,
        is_active=True,
        is_verified=True,
    )
    session.add(analyst)
    await session.flush()

    logger.info(f"✅ Demo analyst created:")
    logger.info(f"   Username : {DEMO_USERNAME}")
    logger.info(f"   Password : {DEMO_PASSWORD}")


async def _seed_sample_alert(session: AsyncSession) -> None:
    """Create one sample alert so the dashboard isn't empty on first load."""
    existing = await session.execute(
        select(Alert).where(Alert.title == "Welcome to ThreatLens AI")
    )
    if existing.scalar_one_or_none():
        return

    welcome_alert = Alert(
        title="Welcome to ThreatLens AI",
        description=(
            "ThreatLens AI is operational. Upload security logs from the Logs page "
            "to begin threat detection. This sample alert can be closed."
        ),
        severity=SeverityLevel.INFO,
        status=AlertStatus.OPEN,
        ai_summary="System initialized successfully. No threats detected.",
        ai_recommendations=[
            "Upload JSON, CSV, or TXT log files from the Logs page.",
            "Review the API documentation at /api/docs.",
            "Create your analyst accounts from the Users page (admin only).",
        ],
        tags=["system", "welcome"],
    )
    session.add(welcome_alert)
    logger.info("✅ Sample welcome alert created.")


if __name__ == "__main__":
    logger.info("Starting ThreatLens AI database seed...")
    asyncio.run(seed_database())
