from typing import Optional
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    
    class Config:
        from_attributes = True
        
class UserLogin(BaseModel):
    username: str
    password: str
    
class TaskResponse(BaseModel):
    id: int
    text: str
    is_completed: bool

class TaskUpdateInfo(BaseModel):
    id: Optional[int] = None
    text: Optional[str] = None
    is_completed: Optional[bool] = None