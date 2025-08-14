from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
import database

class Users(database.Base):
    __tablename__ = "users_unsecure"
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    tasks = relationship("Task", back_populates="user")    
    
class Tasks(database.Base):
    __tablename__ = "tasks_unsecure"
    
    id = Column(Integer, primary_key=True)
    text = Column(String, index=False)
    is_completed = Column(Boolean, index=True, default=False)
    user = relationship("Users", back_populates="tasks")
    