from fastapi import FastAPI, Request, HTTPException, Response, Depends, Body, Cookie, status
from datetime import datetime, timezone, timedelta
import jwt
import time
from pydantic import BaseModel
import sqlite3
import secrets

JWT_SECRET = "secret12343902ijefdjdfskfjldkjvxPMIasd:I£Nsdf)"
conn = sqlite3.connect('database.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()


cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            isPremiumUser BOOL,
            accountDisabled BOOL
            );
""")
conn.commit()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
            );
""")
conn.commit()

def generate_refresh_token():
    return secrets.token_urlsafe(64)

def generate_jwt(user: sqlite3.Row):
    encoded_jwt = jwt.encode({"id": user["id"], "username": user["username"], "role": user["role"], "isPremiumUser": user["isPremiumUser"], "accountDisabled": user["accountDisabled"], "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=30)}, JWT_SECRET, algorithm="HS256")
    return encoded_jwt
    

def validate_jwt(jwt_token):
    try:
        decoded_jwt = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
        return decoded_jwt
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


class User(BaseModel):
    username: str
    password: str

async def protected_endpoint(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Authorization format")
    user = validate_jwt(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    cursor.execute(
    "SELECT accountDisabled FROM users WHERE id = ?", (user["id"],))
    response = cursor.fetchone()
    if not response or response["accountDisabled"]:
        raise HTTPException(status_code=403)
    return user

app = FastAPI()
@app.get("/")
def read_root():
    return "Stuck? Try /docs"

@app.get("/protected")
async def protected_route(user=Depends(protected_endpoint)):
    return {
        "message": "You're authenticated",
        "username": user["username"]
    }

@app.post("/login")
async def user_login(user: User, response: Response):
    cursor.execute("SELECT * FROM users WHERE username = ?", (user.username,))
    result = cursor.fetchone()
    if result:
        username = result["username"]
        password = result["password"]
        if (user.password != password):
            raise HTTPException(status_code=401, detail="Incorrect credentials.")
        access_token = generate_jwt(result)
        refresh_token = generate_refresh_token()
        cursor.execute("INSERT INTO refresh_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)", (result["id"], refresh_token, datetime.now(timezone.utc) + timedelta(days=7), datetime.now(timezone.utc)))
        conn.commit()
        cursor.execute("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ?", (result["id"],))
        session_count = cursor.fetchone()[0]
        if session_count >= 15:
            cursor.execute("DELETE FROM refresh_tokens WHERE id = (SELECT id FROM refresh_tokens WHERE user_id = ? ORDER BY created_at ASC LIMIT 1)", (result["id"],))
            conn.commit()
        
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="strict", path="/refresh")
        return{
            "access_token": access_token,
            "token_type": "bearer"
        }
    else:
        raise HTTPException(status_code=401, detail="Incorrect credentials.")


@app.post('/register', status_code=status.HTTP_200_OK)
async def user_register(user: User):
    try:
        cursor.execute("INSERT INTO users (username, password, role, isPremiumUser, accountDisabled) VALUES (?, ?, 'user', 0, 0)", (user.username, user.password,))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="User already exists")
    return {"status": "OK"}


@app.post("/check-jwt")
async def user_login(jwt_token):
    return validate_jwt(jwt_token)


@app.post("/refresh")
async def refresh_token(response: Response,refresh_token: str = Cookie(None)):
    cursor.execute("SELECT * FROM refresh_tokens WHERE token = ?", (refresh_token,))
    result = cursor.fetchone()

    if not result:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if datetime.now(timezone.utc)> datetime.fromisoformat(result["expires_at"]):
        raise HTTPException(status_code=401, detail="Refresh token expired")
    cursor.execute("SELECT * FROM users WHERE id = ?", (result["user_id"],))
    user = cursor.fetchone()
    if(not user or user["accountDisabled"]):
        raise HTTPException(status_code=403)
    cursor.execute("DELETE FROM refresh_tokens WHERE token = ?", (refresh_token))
    conn.commit()

    new_refresh_token = generate_refresh_token()
    cursor.execute("INSERT INTO refresh_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)", (user["id"], new_refresh_token, datetime.now(timezone.utc) + timedelta(days=30), datetime.now(timezone.utc)))
    conn.commit()
    new_access_token = generate_jwt(user)
    response.set_cookie(key="refresh_token", value=new_refresh_token, httponly=True, secure=False, samesite="strict", path="/refresh")
    return{
            "access_token": new_access_token,
            "token_type": "bearer"
        }