from fastapi import FastAPI

from app.db import engine
from app import models
from app.routes import router
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="DNScope")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


#create database tables on startup (sprint 1 initial approach)
#later on, I'd likely use migrations to ensure that schema changes are tracked, for now, we're doing this to simplify development and focus 
#more on actually validating the data model and logic
models.Base.metadata.create_all(bind=engine)


app.include_router(router)



@app.get("/health")
def health():
    return {"status": "ok"}
