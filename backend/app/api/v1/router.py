"""Main API v1 router - includes all endpoint modules."""
from fastapi import APIRouter

from app.api.v1.endpoints import auth, users, logs, alerts, incidents, reports, dashboard, search

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(logs.router, prefix="/logs", tags=["Log Ingestion"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alert Management"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(search.router, prefix="/search", tags=["Search"])
