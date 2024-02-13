from typing import Union
from fastapi import FastAPI

app = FastAPI()

@app.get("/users/me")
async def read_user_me():
  return {"user_id": "current user"}
