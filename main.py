# This is a test comment to trigger a new commit
from dotenv import load_dotenv  # <-- Add this line
import os
load_dotenv()
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from datetime import datetime, timedelta
import asyncpg
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# --- Authentication Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY")  # Change this in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Database Configuration ---
DATABASE_URL = "postgresql://ar_quotes_db_user:arKtDFpUyFVs8F3myKnvAoHKOj4Jo7FK@dpg-d0plviidbo4c738gbbq0-a.singapore-postgres.render.com/ar_quotes_db?sslmode=require&sslrootcert=config"
pool = None

# --- Pydantic Models ---
class QuoteCreate(BaseModel):
    text: str
    author: str
    latitude: float
    longitude: float
    radius: float

class QuoteResponse(QuoteCreate):
    id: int
    created_at: datetime

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

# --- Database Connection ---
@app.on_event("startup")
async def startup():
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL)

# --- Authentication Utilities ---
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

async def get_user(username: str):
    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1", username
        )
        return user

async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# --- Authentication Routes ---
@app.post("/signup", response_model=dict)
async def signup(user: UserCreate):
    async with pool.acquire() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE email = $1 OR username = $2",
            user.email, user.username
        )
        if exists:
            raise HTTPException(
                status_code=400,
                detail="Username or email already registered"
            )
        
        hashed_password = get_password_hash(user.password)
        new_user = await conn.fetchrow(
            "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email",
            user.username, user.email, hashed_password
        )
        return {"message": "User created successfully", "user": dict(new_user)}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Protected Quote Routes ---
@app.post("/quotes")
async def create_quote(
    quote: QuoteCreate,
    current_user: dict = Depends(get_current_user)
):
    async with pool.acquire() as conn:
        query = """
            INSERT INTO quotes (quote, author, location, radius)
            VALUES ($1, $2, ST_SetSRID(ST_MakePoint($3, $4), 4326), $5)
            RETURNING id, created_at
        """
        result = await conn.fetchrow(
            query, 
            quote.text, 
            quote.author,
            quote.longitude,
            quote.latitude,
            quote.radius
        )
        return {**quote.dict(), "id": result['id'], "created_at": result['created_at']}

# --- Public Quote Routes ---
@app.get("/quotes/nearby")
async def get_nearby_quotes(lat: float, lon: float, distance: int = 100):
    async with pool.acquire() as conn:
        query = """
            SELECT id, quote AS text, author, 
                   ST_X(location::geometry) AS longitude,
                   ST_Y(location::geometry) AS latitude,
                   radius, created_at
            FROM quotes
            WHERE ST_DWithin(
                location,
                ST_SetSRID(ST_MakePoint($1, $2), 4326),
                $3
            )
        """
        return await conn.fetch(query, lon, lat, distance)
