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
    "https://tt-watsonxhackathon-frontend-vdlh.onrender.com"
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
    # Check for existing username (raw SQL)
    check_username_sql = f"SELECT 1 FROM users_unsecure WHERE username = '{user.username}' LIMIT 1"
    result = db.connection().exec_driver_sql(check_username_sql)
    if result.first():
        raise HTTPException(status_code=400, detail='Username is taken.')

    hashed_password = get_hashed_password(user.password)
    # Insert new user (raw SQL)
    insert_user_sql = f"""
        INSERT INTO users_unsecure (username, password)
        VALUES ('{user.username}', '{hashed_password}')
        RETURNING user_id
    """

    result = db.connection().exec_driver_sql(insert_user_sql)
    db.commit()

    return {"message": "Successfully created user"}

@app.get("/users", response_model=UserResponse)
async def get_user(db: db_dependency, response: Response, access_token: Optional[str] = Cookie(default=None)):
    user_id = verify_cookie(response, access_token)
    if not user_id:
        raise HTTPException(status_code=401, detail='User authentication token Expired')
    
    result = db.connection().exec_driver_sql(f"SELECT * FROM users_unsecure WHERE id = '{user_id}' LIMIT 1")
    user = result.mappings().first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found.')
    return {"id": user['id'], "username": user['username']}

@app.post("/login")
async def login(response: Response, db: db_dependency, userdata: UserLogin):
    hashedPwd = get_hashed_password(userdata.password)
    
    # Even more vulnerable - remove password hashing for easier testing
    query = f"SELECT * FROM users_unsecure WHERE username = '{userdata.username}' AND password = '{hashedPwd}'"
    
    try:
        result = db.connection().exec_driver_sql(query)
        user = result.first()
        
        if user:
            access_token = create_access_token(user.id, timedelta(days=3))
            response.set_cookie(key="access_token", value=access_token, httponly=False, secure=False, samesite="lax")
            return {"message": "Login successful"}
        else:
            raise HTTPException(400, "Invalid User Credentials.")
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

    # Insecure raw SQL without text()
    result = db.connection().exec_driver_sql(f"SELECT * FROM users_unsecure WHERE id = {user_id}")
    user = result.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Get tasks for user
    tasks_result = db.connection().exec_driver_sql(f"SELECT * FROM tasks_unsecure WHERE user_id = {user_id}")
    tasks = tasks_result.fetchall()

    # Map tasks to response model
    return [
        {"id": row.id, "text": row.text, "is_completed": row.is_completed}
        for row in tasks
    ]


@app.post("/tasks")
async def update_tasks(
    db: db_dependency,
    taskinfo: TaskUpdateInfo,
    response: Response,
    access_token: Optional[str] = Cookie(default=None)
):
    if taskinfo.id:
        # Update existing task
        if taskinfo.text is not None:
            db.connection().exec_driver_sql(f"""
                UPDATE tasks_unsecure 
                SET text = '{taskinfo.text}' 
                WHERE id = {taskinfo.id}
            """)
        if taskinfo.is_completed is not None:
            db.connection().exec_driver_sql(f"""
                UPDATE tasks_unsecure 
                SET is_completed = {taskinfo.is_completed} 
                WHERE id = {taskinfo.id}
            """)
        db.commit()
    else:
        # Create new task
        user_id = verify_cookie(response, access_token)
        if not taskinfo.text or not user_id:
            raise HTTPException(404, "Error: Cannot create new task without text and user_id")

        is_completed = taskinfo.is_completed is not None and taskinfo.is_completed

        db.connection().exec_driver_sql(f"""
            INSERT INTO tasks_unsecure (text, is_completed, user_id)
            VALUES ('{taskinfo.text}', {is_completed}, {user_id})
        """)
        db.commit()
        
@app.post("/logout")
async def logout(response: Response, access_token: Optional[str] = Cookie(default=None)):
    response.delete_cookie(key="access_token")
    return {"Success": "Logged out successfully."}
    
@app.delete("/tasks/{task_id}")
async def delete_task(db: db_dependency, task_id: int):
    db.connection().exec_driver_sql("DELETE FROM tasks_unsecure WHERE id = '" + str(task_id) + "';")
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

