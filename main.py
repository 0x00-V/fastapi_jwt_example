from fastapi import FastAPI, Request, HTTPException, Depends
from datetime import datetime, timezone, timedelta
import jwt
import time
from pydantic import BaseModel


JWT_SECRET = "secret12343902ijefdjdfskfjldkjvxPMIasd:I£Nsdf)"
users = [
    {"id": 1, "username": "daniel", "password": "iamsecure", "role": "user", "isPremium": False, "accountDisabled": False},
    {"id": 2, "username": "bob", "password": "iamsecure1", "role": "user", "isPremium": False, "accountDisabled": False}
]

def generate_jwt(username, password):
    for user in users:
        if user["username"] == username and user["password"] == password:
            print("Correct credentials")
            print(f"Welcome, {username}. Here's your JWT:")
            encoded_jwt = jwt.encode({"id": user["id"], "username": user["username"], "role": user["role"], "isPremium": user["isPremium"], "accountDisabled": user["accountDisabled"], "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=30)}, JWT_SECRET, algorithm="HS256")
            print(encoded_jwt)
            return encoded_jwt
    print("Incorrect credentials")
    return "Incorrect Credentials"

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

app = FastAPI()
@app.get("/")
def read_root():
    return "Hello world"

async def non_anonymous_user_example(request: Request):
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
    return user

@app.get("/protected")
async def protected_route(user=Depends(non_anonymous_user_example)):
    return {
        "message": "You're authenticated",
        "username": user["username"]
    }


@app.post("/login")
async def user_login(user: User):
    return generate_jwt(user.username, user.password)

@app.post("/check-jwt")
async def user_login(jwt_token):
    return validate_jwt(jwt_token)

