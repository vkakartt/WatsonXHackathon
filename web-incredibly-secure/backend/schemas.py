from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    tenant_ids: list[str]
    
    class Config:
        from_attributes = True
        
class UserLogin(BaseModel):
    username: str
    password: str
    
class MessageInfo(BaseModel):
    message: str
    thread_id: str