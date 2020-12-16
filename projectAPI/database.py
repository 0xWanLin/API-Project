from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base # import SQLAlchemy parts
from sqlalchemy.orm import sessionmaker

# database URL for SQLAlchemy
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:postgres@127.0.0.1:5432/VirusTotal"

# will be using this engine in other files
engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)

# after creating an instance of this class, it will be the actual db session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# will be inheriting this class to create models or classes
Base = declarative_base()
