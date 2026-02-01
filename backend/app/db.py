from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from dotenv import load_dotenv
import os

#load environment variables
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

#fail case if DNScope is unable to reach the database
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")

engine = create_engine(
    DATABASE_URL,
    echo=False, #to not overcrowd logs
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False, #prevents from automatically writing partial changes
    autocommit=False, #allows us to control when changes are saved
)

class Base(DeclarativeBase):
    pass