from datetime import timedelta, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from starlette import status
from database import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from models import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from config import Config
from sqlmodel import select

"""
OAuth2PasswordRequestForm: This collects the users login info via form data (username, password, etc.).
OAuth2PasswordBearer: This handles bearer token authentication for future requests.
"""

SECRET_KEY = Config.JWT_SECRET
ALGORITHM = Config.JWT_ALGORITHM
ACCESS_TOKEN_EXPIRY = 3600

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated = "auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

router = APIRouter(prefix="/auth", tags=['auth'])

class CreateUserRequest(BaseModel):
    username:str
    password : str

class Token(BaseModel):
    access_token: str
    token_type: str

MyAsyncSession = Annotated[AsyncSession, Depends(get_session)]

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(user_data: CreateUserRequest, session: MyAsyncSession):
        new_user = User(
             username=user_data.username,
             password_hash = bcrypt_context.hash(user_data.password)
             )
        session.add(new_user)
        await session.commit()
        return new_user

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: MyAsyncSession):
     user = await authenticate_user(form_data.username, form_data.password, session)
     if not user:
          raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user")
     token = create_access_token(user.username, str(user.uid))
     return {"access_token" : token, "token_type" : "bearer"}

async def authenticate_user(user_name : str, password : str, session: MyAsyncSession):
     statement = select(User).where(User.username == user_name)
     result = await session.exec(statement)
     user = result.first()
     if not user:
          return False
     if not bcrypt_context.verify(password, user.password_hash):
          return False
     return user

def create_access_token(username : str, user_id : str , expires_delta: timedelta = None):
     encode = {"sub": username, "id": user_id}
     expires = datetime.now() + (expires_delta if expires_delta else timedelta(seconds=ACCESS_TOKEN_EXPIRY))
     encode.update({"exp" : expires})
     return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)

async def get_current_user(token : Annotated[str, Depends(oauth2_bearer)]):
     try:
          payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
          username : str = payload.get("sub")
          user_id : str = payload.get("id")
          if username is None or user_id is None:
               raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail= "Could not validate user")
          return {"username" : username, "id" : user_id}
     except JWTError:
          raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user")