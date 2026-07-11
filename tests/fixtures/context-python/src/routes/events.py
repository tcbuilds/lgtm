from fastapi import APIRouter
from app.auth import require_user

router = APIRouter()

@router.post("/events")
def create_event():
    pass
