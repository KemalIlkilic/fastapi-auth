from fastapi import FastAPI, status, Depends, HTTPException
import models
from contextlib import asynccontextmanager
from database import init_db
from typing import Annotated
from database import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from auth import router, get_current_user


@asynccontextmanager
async def life_span(app : FastAPI):
    #doing smth after server start
    print("Server is starting...")
    await init_db()
    yield
    #doing smth before server end
    print("Server is ending...")


version = "v1"

app = FastAPI(
    title="Bookly",
    description="A REST API for a book review web service",
    version=version,
    lifespan=life_span
)
app.include_router(router)

MyAsyncSession = Annotated[AsyncSession, Depends(get_session)]
user_dependency = Annotated[dict, Depends(get_current_user)]



@app.get("/", status_code=status.HTTP_200_OK)
async def user (user : user_dependency , db : MyAsyncSession):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return {"User" : user}