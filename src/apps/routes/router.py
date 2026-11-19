from fastapi import APIRouter

from src.apps.routes.v1.auth_routes import router as auth_router


api_router = APIRouter()

api_router.include_router(auth_router)
