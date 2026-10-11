from http.client import HTTPException

from fastapi import FastAPI,Depends , HTTPException
from passlib.context import CryptContext 
from jose import jwt  
from dotenv import load_dotenv
import json
import os
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer

# FASTAPI instance
app = FastAPI(
title="Gym Application API",
description="This is a Gym Application API built with FastAPI.",
version="1.0.0"
)

# password= Test@123
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

    return plain_password == hashed_password  # Placeholder, replace with actual verification logic
def create_access_token(data: dict, secret_key: str, algorithm: str) -> str:
    return jwt.encode(data, secret_key, algorithm=algorithm)

class RegisterRequest(BaseModel):
    email: str
    password: str
    
load_dotenv()

@app.post("/register")
def register_user(request: RegisterRequest):
    # check if the user already exists in the database (users.json)
    with open(USERS_FILE, "r+", encoding="utf-8") as file:
        contents = file.read()
        users_data = json.loads(contents)
        for user in users_data["users"]:
            if user["email"] == request.email:
                return {"message": "User already exists."}
    
        hashed_password = hash_password(request.password)
        user_data = {
            "email": request.email, 
            "password": hashed_password
        }
        users_data["users"].append(user_data)

        file.seek(0)
        json.dump(users_data, file, indent=2)
        file.truncate()

    return {"message": "User registered successfully."}

@app.post("/login")
def login_user(request: RegisterRequest):
    # check if the user exists in the database (users.json)
    with open(USERS_FILE, "r", encoding="utf-8") as file:
        users_data = json.load(file) 
        for user in users_data["users"]:
            # check if the email matches
            if user["email"] == request.email:
                #verify the password
                if verify_password(request.password, user["password"]):
                    secret_key = os.getenv("SECRET_KEY")
                    algorithm = os.getenv("ALGORITHM")
                    access_token = create_access_token({"sub": request.email}, secret_key, algorithm)
                    return {"access_token": access_token, "token_type": "bearer"}
                else:
                    return {"message": "Invalid password."}
            
        return {"message": "User not found."}
                

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
def get_current_user(token: str = Depends(oauth2_scheme)):
    
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials"
    )
    secret_key = os.getenv("SECRET_KEY")
    algorithm = os.getenv("ALGORITHM")
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
            
        return email
    except jwt.JWTError:
        raise credentials_exception
# protected route to get user profile

@app.get("/profile")
def get_profile(current_user: str = Depends(get_current_user)):
    return {"email": current_user}  


# dependency injection 
def get_userName():
    return "John Doe"

@app.get("/greet")
def greet_user(user_name: str = Depends(get_userName)):
    return {"message": f"Hello, {user_name}!"}