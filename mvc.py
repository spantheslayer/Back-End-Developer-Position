# Import necessary modules
from typing import List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
import hashlib

# Initialize FastAPI app
app = FastAPI()

# SQLAlchemy database connection
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://username:password@localhost/db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Secret Key
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Dependency to get the current session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Dependency to extract token from request headers
async def get_token(authorization: str = Depends(oauth2_scheme)):
    if authorization is None or len(authorization.split()) != 2:
        return None
    scheme, token = authorization.split()
    if scheme.lower() != "bearer":
        return None
    return token


# Dependency to get current user from token
async def get_current_user(token: str = Depends(get_token)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return email


# Pydantic models
class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class PostBase(BaseModel):
    text: str


class PostCreate(PostBase):
    pass


class PostOut(PostBase):
    id: int
    created_at: datetime


# Hashing password
def get_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Database Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)


class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(String)
    user_id = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)


if __name__ == "__main__":
    # Create a SQLAlchemy engine
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

    # Declare a base class for ORM models
    Base = declarative_base()

    # Define the User model
    class User(Base):
        __tablename__ = "users"

        id = Column(Integer, primary_key=True, index=True)
        email = Column(String, unique=True, index=True)
        hashed_password = Column(String)
        Base.metadata.create_all(bind=engine)


# Create user endpoint
@app.post("/signup", response_model=Token)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"access_token": new_user.email, "token_type": "bearer"}


# Login endpoint
@app.post("/login", response_model=Token)
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or user.hashed_password != get_password_hash(password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    return {"access_token": user.email, "token_type": "bearer"}


# Add post endpoint
@app.post("/add_post", response_model=PostOut)
def add_post(post: PostCreate, token: str = Depends(get_current_user), db: Session = Depends(get_db)):
    # Token authentication logic
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Check payload size
    if len(post.text) > 1024 * 1024:  # 1 MB limit
        raise HTTPException(status_code=400, detail="Payload size exceeds limit")
    # Save post to the database
    db_post = Post(text=post.text, user_id=1)  # Assuming user_id is 1 for now
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post


# Get posts endpoint
@app.get("/get_posts", response_model=List[PostOut])
def get_posts(token: str = Depends(get_current_user), db: Session = Depends(get_db)):
    # Token authentication logic
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Query posts from database
    posts = db.query(Post).filter(Post.user_id == 1).all()  # Assuming user_id is 1 for now
    return posts


# Delete post endpoint
@app.delete("/delete_post/{post_id}")
def delete_post(post_id: int, token: str = Depends(get_current_user), db: Session = Depends(get_db)):
    # Token authentication logic
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Find post in database
    post = db.query(Post).filter(Post.id == post_id, Post.user_id == 1).first()  # Assuming user_id is 1 for now
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    # Delete post
    db.delete(post)
    db.commit()
    return {"message": "Post deleted successfully"}
