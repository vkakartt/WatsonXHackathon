from fastapi import FastAPI, HTTPException, Depends, Request, Response, Cookie
from fastapi.responses import JSONResponse
import requests
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta
from typing import Annotated, Optional

from sqlalchemy import select
import models
from models import *
import database
from database import engine, get_db
from sqlalchemy.orm import Session
from schemas import *
from json import dumps
from helpers import *

app = FastAPI()
origins = [
    "http://localhost:3000"
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

@app.get("/zap/{subpath:path}")
async def zap_proxy(subpath: str, request: Request):
    # Construct target ZAP URL
    zap_url = f"{ZAP_API_URL}/{subpath}?apikey={ZAP_API_KEY}"

    print(zap_url)
    # Forward query parameters, add API key
    params = dict(request.query_params)

    # Make the actual ZAP request
    try:
        resp = requests.get(zap_url, params=params)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
    
@app.post("/zap/{subpath:path}")
async def zap_post_proxy(subpath: str, request: Request):
    # Construct the full ZAP endpoint URL
    zap_url = f"{ZAP_API_URL}/{subpath}?apikey={ZAP_API_KEY}"

    # Read query parameters from the original request
    params = dict(request.query_params)

    # Read request body (handles JSON, form, etc.)
    body = await request.body()
    headers = {
        "Content-Type": request.headers.get("content-type", "application/json")
    }

    try:
        # Forward the request to ZAP as a POST
        zap_response = requests.post(
            zap_url,
            params=params,
            data=body,
            headers=headers
        )

        # Return the response from ZAP
        return JSONResponse(
            status_code=zap_response.status_code,
            content=zap_response.json()
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )


@app.post("/users")
async def create_user(user: UserCreate, db: db_dependency):
    # Check for existing username
    if db.query(models.Users).filter(models.Users.username == user.username).first():
        raise HTTPException(status_code=400, detail='Username is taken.')
    
    # Create user with auto-generated user_id
    db_user = models.Users(
        username=user.username, 
        password=get_hashed_password(user.password),
        thread_ids=[]
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)  # This gets the auto-generated user_id
    return {"message": "Successfully created user"}

@app.get("/users", response_model=UserResponse)
async def get_user(db: db_dependency, response: Response, access_token: Optional[str] = Cookie(default=None), refresh_token: Optional[str] = Cookie(default=None)):
    user_id = verify_cookie(response, access_token, refresh_token)
    if not user_id:
        raise HTTPException(status_code=401, detail='User authentication token Expired')
    
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found.')
    return user

@app.post("/login")
async def login(response: Response, user_credentials: UserLogin, db: db_dependency):
    user = db.query(models.Users).filter((models.Users.username == user_credentials.username)).first()
    if (not user):
        raise HTTPException(status_code=401, detail="Invalid Username.")
    
    success = check_password(user_credentials.password, user.password)
    
    if not success:
        raise HTTPException(status_code=401, detail="Incorrect Password.")
    
    access_token = create_access_token(user.id)
    refresh_token = create_access_token(user.id, timedelta(days=3))
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax")
    return {"message":"Logged in successfully"}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token");
    response.delete_cookie(key="refresh_token");
    return {"message":"Logged out successfully"}

@app.post("/orchestrate/thread")
async def create_thread(db: db_dependency):
    url = "/orchestrate/threads"
    method = "POST"
    body = {"agent_id": "96adbe39-6327-4247-b102-6fbabd97a652"}
    print("test")
    try:
        return await makeApiCall(url, method, payload=body)
    except Exception as e:
        print("test2")
        raise e

@app.get("/orchestrate/threads/{thread_id}")
async def get_message_history(db: db_dependency, thread_id: str):
    url = f"/orchestrate/threads/{thread_id}/messages"
    headers = {"Content-Type": "application/json"}
    
    try:
        response = await makeApiCall(url, "GET", headers)
    except Exception as e:
        raise e
    
    messages = []
    for message in response:
        if type(message) == str:
            raise HTTPException(500, message)
        if message['content']:
            messages.append({
                "is_user": message['role']=='user',
                "message": message['content'][0]['text'],
                "timestamp": message['updated_at']
            })
    return messages

@app.post("/orchestrate/message")
async def send_message(db: db_dependency, message_info: MessageInfo, response: Response, refresh_token: Optional[str] = Cookie(default=None), access_token: Optional[str] = Cookie(default=None)):
    user_id = verify_cookie(response, access_token, refresh_token)
    if not user_id:
        raise HTTPException(401, "User session expired.")
    
    url = "/orchestrate/runs"
    headers = {"Content-Type":"application/json"}
    params = {"multiple_content": False, "stream": False, "stream_timeout": 60000}
    payload = {
        "message": {
            "role":"user",
            "content": message_info.message
        },
        "agent_id": "96adbe39-6327-4247-b102-6fbabd97a652",
        "thread_id": message_info.thread_id
    }
    try:
        response = await makeApiCall(url, "POST", headers, params, payload)
        print("testing")
        if message_info.thread_id is None:
            result = db.query(models.Users).filter(models.Users.id == user_id).first()
            if not result:
                raise HTTPException(404, "User does not exist.")
            result.thread_ids = result.thread_ids + [response['thread_id']]
            print(result.thread_ids)
            db.commit()
    except Exception as e:
        raise e
    url += f"/{response['run_id']}"
    while True:
        try:
            response2 = await makeApiCall(url, "GET")
        except Exception as e:
            raise e
        
        if not response2:
            raise HTTPException(500, "Could not recieve message.")
        if response2['status'] == "completed":
            return {"message":response2['result']['data']['message']['content'][0]['text'], "thread_id": response2['thread_id']}
        
