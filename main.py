from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from pydantic import BaseModel
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware


class UserLogin(BaseModel):
    username: str
    password: str


app = FastAPI()

# Enable CORS for all origins. Adjust the parameters based on your security requirements.
origins = [
    "http://localhost",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
# MongoDB settings
MONGODB_URL = "mongodb://localhost:27017"
DATABASE_NAME = "fast_api_db"
USERS_COLLECTION = "users"

# FastAPI settings
SECRET_KEY = "MY_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2PasswordBearer is used for handling token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB client
client = AsyncIOMotorClient(MONGODB_URL)
db = client[DATABASE_NAME]
users_collection = db[USERS_COLLECTION]


# User model
class User(BaseModel):
    name: str
    email: str
    username: str
    hashed_password: str


# Function to create JWT token
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Dependency to get the current user from the token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username


# Route to create a new user
@app.post("/register")
async def register(name: str, email: str, username: str, password: str):
    hashed_password = pwd_context.hash(password)
    user = {"username": username, "hashed_password": hashed_password, "name": name, "email": email}
    await users_collection.insert_one(user)
    return {"message": "User registered successfully"}


# Route to get a token (login)
@app.post("/token")
async def login_for_access_token(username: str, password: str):
    user = await users_collection.find_one({"username": username})
    if not user or not pwd_context.verify(password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate a JWT token
    token_data = {"sub": username}
    return {"access_token": create_access_token(token_data), "token_type": "bearer"}


# Example protected route
@app.get("/protected-route")
async def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": "This is a protected route", "current_user": current_user}
