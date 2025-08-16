from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import database_exists, create_database

DATABASE_URL = 'postgresql://tt_watsonxhackathon_maindb_user:1ZXq0AFS5PPIgLpSKNYw3ZL0KPg3ZXO6@dpg-d2ee3649c44c738sm56g-a.ohio-postgres.render.com/tt_watsonxhackathon_maindb'

engine = create_engine(DATABASE_URL)
if not database_exists(engine.url):
    # create_database(engine.url)
    print("Databse does not exist")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()