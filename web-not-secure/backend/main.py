from fastapi import FastAPI, HTTPException, Depends, Response, Cookie, Form
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import date, datetime, timedelta, timezone
from typing import List, Annotated, Optional

from sqlalchemy import select, text
import models
from models import *
import database
from database import engine, get_db
from sqlalchemy.orm import Session
from schemas import *
import jwt
from json import dumps
from jwt.exceptions import InvalidTokenError
import hashlib

app = FastAPI()
origins = [
    "*"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,  # Allow cookies and credentials to be sent
    allow_methods=["*"],     # Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],     # Allow all headers in the request
)
    
database.Base.metadata.create_all(bind=engine)

db_dependency = Annotated[Session, Depends(get_db)]

SECRET_KEY = "aaef54aee7ea6b3df86e50f888a8d2c7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


@app.post("/users")
async def create_user(user: UserCreate, db: db_dependency):
    # Check for existing username
    if db.query(models.Users).filter(models.Users.username == user.username).first():
        raise HTTPException(status_code=400, detail='Username is taken.')
    
    # Create user with auto-generated user_id
    db_user = models.Users(
        username=user.username, 
        password=get_hashed_password(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)  # This gets the auto-generated user_id
    return {"message": "Successfully created user"}

@app.get("/users", response_model=UserResponse)
async def get_user(db: db_dependency, response: Response, access_token: Optional[str] = Cookie(default=None)):
    user_id = verify_cookie(response, access_token)
    if not user_id:
        raise HTTPException(status_code=401, detail='User authentication token Expired')
    
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found.')
    return user

@app.post("/login")
async def login(response: Response, db: db_dependency, userdata: UserLogin):
    hashedPwd = get_hashed_password(userdata.password)
    
    # Even more vulnerable - remove password hashing for easier testing
    query = f"SELECT * FROM users_unsecure WHERE username = '{userdata.username}' AND password = '{hashedPwd}'"
    print(f"Executing query: {query}")  # Debug output
    
    try:
        result = db.execute(text(query))
        user = result.first()
        
        if user:
            access_token = create_access_token(user.id, timedelta(days=3))
            response.set_cookie(key="access_token", value=access_token, httponly=False, secure=False, samesite="lax")
            return {"message": "Login successful", "redirect": "http://localhost:3000/home"}
        else:
            raise HTTPException(400, "Invalid user credentials.")
    except Exception as e:
        print(f"SQL Error: {e}")
        raise HTTPException(400, "Invalid User Credentials")
    
@app.get("/tasks", response_model=List[TaskResponse])
async def get_tasks(
    db: db_dependency,
    response: Response,
    access_token: Optional[str] = Cookie(default=None)
):
    user_id = verify_cookie(response, access_token)
    if not user_id:
        raise HTTPException(401, "Unauthorized")

    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    return user.tasks

@app.post("/tasks")
async def update_tasks(db: db_dependency, taskinfo: TaskUpdateInfo, response: Response, access_token: Optional[str] = Cookie(default=None)):
    if taskinfo.id:
        task = db.query(models.Tasks).filter(models.Tasks.id == taskinfo.id).first()
        if taskinfo.text is not None:
            task.text = taskinfo.text
        if taskinfo.is_completed is not None:
            task.is_completed = taskinfo.is_completed
        db.commit()
    else:
        user_id = verify_cookie(response, access_token)
        if not taskinfo.text or not user_id:
            raise HTTPException(404, "Error: Cannot create new task wihtout txt and userid")
        db_task = models.Tasks(
            text=taskinfo.text,
            is_completed=taskinfo.is_completed is not None and taskinfo.is_completed,
            user_id=user_id
        )
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
    
@app.delete("/tasks/{task_id}")
async def delete_task(db: db_dependency, task_id: int):
    db.execute(text("DELETE FROM tasks_unsecure WHERE id = '" + str(task_id) + "';"))
    db.commit()
    return {"Success": "Deleted message"}
    
    
def get_hashed_password(plain_text_password):
    password_bytes = plain_text_password.encode('utf-8')
    return hashlib.sha256(password_bytes).hexdigest()

def create_access_token(user_id: int, expires_delta: timedelta | None = None):
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
        
    payload = {
        "user_id": user_id,
        "expires": expire.isoformat()
    }
    
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
    
def decode_jwt(token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_token, (datetime.fromisoformat(decoded_token["expires"]) >= datetime.now(timezone.utc))
    except:
        return None, False

def verify_cookie(response: Response, access_token: Optional[str] = Cookie(default=None)):
    if not access_token:
        return None
    
    # Try to decode access token first
    result, success = decode_jwt(access_token)
    if success and result and "user_id" in result:
        return result["user_id"]
    
    # token failed - clear cookies
    response.delete_cookie(key="access_token")
    return None

