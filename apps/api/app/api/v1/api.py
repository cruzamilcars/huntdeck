from fastapi import APIRouter

from app.api.v1.routes import investigations

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(investigations.router)
