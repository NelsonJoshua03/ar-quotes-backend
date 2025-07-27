# AR Quotes API - Production Ready
from dotenv import load_dotenv
import os
import logging
import asyncio
load_dotenv()
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from datetime import datetime, timedelta
import asyncpg
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Configure robust logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Security Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    logger.critical("SECRET_KEY environment variable is not set")
    raise RuntimeError("Missing SECRET_KEY - generate with: openssl rand -hex 32")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="AR Quotes API",
    description="Backend for geolocated augmented reality quotes",
    version="1.0.0"
)

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Database Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.critical("DATABASE_URL environment variable is not set")
    raise RuntimeError("Missing DATABASE_URL - get from Render.com")

# Add sslmode=require if missing
if "sslmode" not in DATABASE_URL and "render.com" in DATABASE_URL:
    DATABASE_URL += "?sslmode=require"
    logger.info("Added sslmode=require to DATABASE_URL")

logger.info(f"Database URL: {DATABASE_URL.split('@')[-1]}")

pool = None

# --- Data Models ---
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

# --- Database Initialization ---
@app.on_event("startup")
async def startup():
    global pool
    logger.info("Initializing database connection...")
    
    try:
        # Create connection pool
        pool = await asyncpg.create_pool(
            dsn=DATABASE_URL,
            min_size=1,
            max_size=10,
            command_timeout=30
        )
        logger.info("Database connection pool created")
        
        # Initialize database schema with retries
        retry_count = 0
        max_retries = 5
        while retry_count < max_retries:
            try:
                await initialize_database()
                logger.info("Database initialization successful")
                return
            except Exception as e:
                retry_count += 1
                logger.error(f"Database init failed (attempt {retry_count}/{max_retries}): {str(e)}")
                await asyncio.sleep(1)
        
        logger.critical("Database initialization failed after multiple attempts")
        raise RuntimeError("Database setup failed after retries")
        
    except Exception as e:
        logger.exception("Startup failed")
        raise RuntimeError(f"Database setup error: {str(e)}")

async def initialize_database():
    """Create database tables and indexes if needed"""
    async with pool.acquire() as conn:
        # Check if users table exists
        users_exists = await conn.fetchval(
            "SELECT EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users')"
        )
        
        if not users_exists:
            logger.info("Creating users table...")
            await conn.execute('''
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            logger.info("Users table created")
        else:
            logger.info("Users table already exists")
        
        # Check if quotes table exists
        quotes_exists = await conn.fetchval(
            "SELECT EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'quotes')"
        )
        
        if not quotes_exists:
            logger.info("Creating quotes table...")
            await conn.execute('''
                CREATE TABLE quotes (
                    id SERIAL PRIMARY KEY,
                    quote TEXT NOT NULL,
                    author VARCHAR(100) NOT NULL,
                    longitude FLOAT NOT NULL,
                    latitude FLOAT NOT NULL,
                    radius FLOAT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            logger.info("Quotes table created")
        else:
            logger.info("Quotes table already exists")
        
        # Create index for location queries
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS quotes_location_idx 
            ON quotes (longitude, latitude)
        ''')
        logger.info("Location index verified")

# --- Security Utilities ---
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

async def get_user(username: str):
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1", username
        )

async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError as e:
        logger.warning(f"JWT error: {str(e)}")
        raise credentials_exception
    
    user = await get_user(username)
    if not user:
        logger.warning(f"User not found: {username}")
        raise credentials_exception
    return user

# --- API Endpoints ---
@app.get("/")
async def health_check():
    return {
        "status": "running",
        "service": "AR Quotes API",
        "version": "1.0.0",
        "time": datetime.utcnow().isoformat(),
        "database": "connected" if pool else "disconnected"
    }

@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate):
    try:
        async with pool.acquire() as conn:
            # Check for existing user
            exists = await conn.fetchval(
                "SELECT 1 FROM users WHERE email = $1 OR username = $2",
                user.email, user.username
            )
            if exists:
                raise HTTPException(
                    status_code=400,
                    detail="Username or email already exists"
                )
            
            # Hash password
            hashed_password = get_password_hash(user.password)
            
            # Create user
            new_user = await conn.fetchrow(
                "INSERT INTO users (username, email, password_hash) "
                "VALUES ($1, $2, $3) RETURNING id, username, email",
                user.username, user.email, hashed_password
            )
            return {
                "message": "User created successfully",
                "user": dict(new_user)
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Signup failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="User registration failed. Please try again later."
        )

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        logger.warning(f"Login failed for user: {form_data.username}")
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token, "token_type": "bearer"}

@app.post("/quotes", status_code=status.HTTP_201_CREATED)
async def create_quote(
    quote: QuoteCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        async with pool.acquire() as conn:
            # Insert new quote
            result = await conn.fetchrow(
                """
                INSERT INTO quotes (quote, author, longitude, latitude, radius)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, created_at
                """, 
                quote.text, 
                quote.author,
                quote.longitude,
                quote.latitude,
                quote.radius
            )
            return {
                "message": "Quote created",
                "id": result['id'],
                "text": quote.text,
                "author": quote.author,
                "latitude": quote.latitude,
                "longitude": quote.longitude,
                "radius": quote.radius,
                "created_at": result['created_at']
            }
    except Exception as e:
        logger.error(f"Quote creation failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to create quote"
        )

@app.get("/quotes/nearby")
async def get_nearby_quotes(lat: float, lon: float, distance: int = 100):
    """
    Find quotes within exact distance (in meters) using Haversine formula
    """
    try:
        async with pool.acquire() as conn:
            # Use Haversine formula for accurate distance calculation
            quotes = await conn.fetch(
                """
                SELECT 
                    id, 
                    quote AS text, 
                    author, 
                    latitude, 
                    longitude,
                    radius, 
                    created_at AS createdAt,
                    id::text AS locationId,
                    -- Calculate exact distance for potential client-side use
                    6371000 * 2 * ASIN(
                        SQRT(
                            POWER(SIN(RADIANS(latitude - $1) / 2), 2) +
                            COS(RADIANS($1)) * 
                            COS(RADIANS(latitude)) *
                            POWER(SIN(RADIANS(longitude - $2) / 2), 2)
                        )
                    ) AS distance_meters
                FROM quotes
                WHERE 
                    6371000 * 2 * ASIN(
                        SQRT(
                            POWER(SIN(RADIANS(latitude - $1) / 2), 2) +
                            COS(RADIANS($1)) * 
                            COS(RADIANS(latitude)) *
                            POWER(SIN(RADIANS(longitude - $2) / 2), 2)
                        )
                    ) <= $3
                """,
                lat, lon, distance
            )
            return [dict(q) for q in quotes]
    except Exception as e:
        logger.error(f"Nearby quotes query failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve nearby quotes"
        )

# --- Diagnostic Endpoints ---
@app.get("/test-db")
async def test_db():
    """Test database connection and basic operations"""
    try:
        async with pool.acquire() as conn:
            # Test connection
            db_time = await conn.fetchval("SELECT NOW()")
            
            # Test users table
            user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
            
            # Test quotes table
            quote_count = await conn.fetchval("SELECT COUNT(*) FROM quotes")
            
            # Test quote insertion
            test_quote = await conn.fetchrow(
                "INSERT INTO quotes (quote, author, longitude, latitude, radius) "
                "VALUES ($1, $2, $3, $4, $5) RETURNING id",
                'Test quote', 'System', 0.0, 0.0, 10
            )
            await conn.execute("DELETE FROM quotes WHERE id = $1", test_quote['id'])
            
            return {
                "status": "success",
                "database_time": str(db_time),
                "user_count": user_count,
                "quote_count": quote_count,
                "test_quote_id": test_quote['id']
            }
    except Exception as e:
        logger.exception(f"Test DB failed: {str(e)}")
        return {
            "status": "error",
            "detail": str(e)
        }

@app.get("/env-check")
async def env_check():
    """Verify critical environment variables"""
    return {
        "DATABASE_URL_set": bool(os.getenv("DATABASE_URL")),
        "SECRET_KEY_set": bool(os.getenv("SECRET_KEY")),
        "database_ssl": "require" in DATABASE_URL.lower() if DATABASE_URL else False
    }
