from fastapi import APIRouter

from app.api.v1.routes import investigations, system, watchlist

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(investigations.router)
api_router.include_router(watchlist.router)
api_router.include_router(system.router)
