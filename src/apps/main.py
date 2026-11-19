from fastapi import APIRouter

api_router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

@api_router.get("/test")
async def auth_test():
    return {
        "message": "Authentication route working"
    }