import subprocess
import asyncio
from datetime import datetime, timedelta, timezone
import os
import threading
import time
from typing import Optional
import bcrypt
from fastapi import Cookie, HTTPException, Response
import requests
import jwt

SECRET_KEY = "aaef54aee7ea6b3df86e50f888a8d2c7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

AUTH_TOKEN = "eyJraWQiOiIyMDE5MDcyNCIsImFsZyI6IlJTMjU2In0.eyJpYW1faWQiOiJJQk1pZC02OTIwMDBZWEZLIiwiaWQiOiJJQk1pZC02OTIwMDBZWEZLIiwicmVhbG1pZCI6IklCTWlkIiwianRpIjoiMzIzYWEzOTYtYjllZS00MTVjLTk5OGEtMzQ5ZmIyNjMyYjQ1IiwiaWRlbnRpZmllciI6IjY5MjAwMFlYRksiLCJnaXZlbl9uYW1lIjoiVmVlciIsImZhbWlseV9uYW1lIjoiS2FrYXIiLCJuYW1lIjoiVmVlciBLYWthciIsImVtYWlsIjoidmVlci5rYWthckB0cmFuc2Zvcm1hdGVjaC5jb20iLCJzdWIiOiJ2ZWVyLmtha2FyQHRyYW5zZm9ybWF0ZWNoLmNvbSIsImF1dGhuIjp7InN1YiI6InZlZXIua2FrYXJAdHJhbnNmb3JtYXRlY2guY29tIiwiaWFtX2lkIjoiSUJNaWQtNjkyMDAwWVhGSyIsIm5hbWUiOiJWZWVyIEtha2FyIiwiZ2l2ZW5fbmFtZSI6IlZlZXIiLCJmYW1pbHlfbmFtZSI6Iktha2FyIiwiZW1haWwiOiJ2ZWVyLmtha2FyQHRyYW5zZm9ybWF0ZWNoLmNvbSJ9LCJhY2NvdW50Ijp7InZhbGlkIjp0cnVlLCJic3MiOiJlOGM2ZmVlNTRmNDE0MmIyYjFiOWJhYzY0OTRjZmJjOCIsImltc191c2VyX2lkIjoiMTQyNTUzMzMiLCJmcm96ZW4iOnRydWUsImltcyI6IjI5OTY5MzgifSwiaWF0IjoxNzU1MzU2OTM4LCJleHAiOjE3NTUzNjA1MzgsImlzcyI6Imh0dHBzOi8vaWFtLmNsb3VkLmlibS5jb20vaWRlbnRpdHkiLCJncmFudF90eXBlIjoidXJuOmlibTpwYXJhbXM6b2F1dGg6Z3JhbnQtdHlwZTphcGlrZXkiLCJzY29wZSI6ImlibSBvcGVuaWQiLCJjbGllbnRfaWQiOiJkZWZhdWx0IiwiYWNyIjoxLCJhbXIiOlsicHdkIl19.Oiga2cq1WsfzIJe5JXUUFKTOlWQioK4f_6VaHj6AZfC7l00Tl3HrQE35qOhisun5yw91vexaWYqPb-ohqpGh3ov18e0TkVncu-VyguQP7Oe6PfCC4ijgAIRbsXacA4wN-u7fWdXy9rrMM506w3y8BQWrKmxtfDfV0i-3qs97gnn9W1Sk3eSTljgD7AaXUmcGvt-7dIBNm22o0OelyNlD4XR1s5CbAdlLS3mKlo_n6tINiGqjQCF-iaVbcrN0yPhbs3cpOqYTMPZkzAO2B8NF0bJaaSCGOCDJ_hVOjt4Nk5PgT03DPEebQFsQd05sNvo8fZGFZrobyOMIOkqf9G2xhw"
BASE_URL = "https://api.ca-tor.watson-orchestrate.cloud.ibm.com/instances/1a32ff28-f8a6-416a-a329-07d5b40715c9/v1"

ZAP_API_KEY = "aaef54aee7ea6b3df86e50f888a8d2c7"
ZAP_API_URL = "http://127.0.0.1:8090"

async def makeApiCall(url: str, method, headers=None, params=None, payload=None):
    global AUTH_TOKEN
    if headers:
        headers['Authorization'] = f"Bearer {AUTH_TOKEN}"
    else:
        headers = {"Authorization" : f"Bearer {AUTH_TOKEN}"}

    # yes this is necessary
    for i in range(5): 
        if i == 3 and not start_env():
            print("Error: could not start orchestrate env")
            raise HTTPException(400, "unknown user error")
        if i == 2:
            headers2 = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {"grant_type":"urn:ibm:params:oauth:grant-type:apikey", "apikey":"TFQpwuwvqQiOcBceK3uwRr8kmaDfZ6dzV_6C9sklYY8o"}
            key_response = requests.post("https://iam.cloud.ibm.com/identity/token", headers=headers2, data=data)
            key_response_json = key_response.json()
            if key_response_json['access_token']:
                AUTH_TOKEN=key_response_json['access_token']
        try:
            if method == "GET":
                response = requests.get(BASE_URL + url, headers=headers, params=params)
            elif method == "POST":
                response = requests.post(BASE_URL + url, headers=headers, params=params, json=payload)
            else:
                print("why")
                raise HTTPException(400, "Bad Request.")
            print(response.json())
            if "code" not in response.json():
                return response.json()
        except Exception as e:
            print("Failed to call. Trying again.")
            print(e)
            if i == 4:
                raise e
    raise HTTPException(500, response.json())

def start_env():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    env_dir = os.path.join(base_dir, '..', '.venv', 'scripts','python.exe')
    print(env_dir)
    API_KEY = "TFQpwuwvqQiOcBceK3uwRr8kmaDfZ6dzV_6C9sklYY8o"
    ENV_NAME = "Not-Coding"
    COMMAND = ["python","-m","orchestrate", "env", "activate", ENV_NAME, '--api-key', API_KEY]
    
    # Start subprocess with pipes for stdin and stdout
    process = subprocess.Popen(
        COMMAND,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    
    if process.poll() is None:
        process.wait(timeout=30)
    
    return process.returncode == 0    
    
def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    password_bytes = plain_text_password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode('utf-8')

def check_password(plain_text_password, hashed_password):
    password_bytes = plain_text_password.encode('utf-8')
    # Convert base64 string back to bytes
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

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

def verify_cookie(response: Response, access_token: Optional[str] = Cookie(default=None), refresh_token: Optional[str] = Cookie(default=None)):
    if not access_token or not refresh_token:
        return None
    
    # Try to decode access token first
    result, success = decode_jwt(access_token)
    if success and result and "user_id" in result:
        return result["user_id"]
    
    # If access token failed, try refresh token
    refresh, refresh_success = decode_jwt(refresh_token)
    if refresh_success and refresh and "user_id" in refresh:
        # Create new access token using user_id from refresh token
        new_access_token = create_access_token(refresh["user_id"])
        response.set_cookie(key="access_token", value=new_access_token, httponly=True, secure=False, samesite="lax")
        return refresh["user_id"]
    
    # Both tokens failed - clear cookies
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return None