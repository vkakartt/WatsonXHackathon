from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
import database

class Users(database.Base):
    __tablename__ = "users_unsecure"
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    tasks = relationship("Tasks", back_populates="user", cascade="all, delete-orphan") 
    
class Tasks(database.Base):
    __tablename__ = "tasks_unsecure"
    
    id = Column(Integer, primary_key=True)
    text = Column(String, index=False)
    is_completed = Column(Boolean, index=True, default=False)
    user_id = Column(Integer, ForeignKey("users_unsecure.id"), nullable=False)
    user = relationship("Users", back_populates="tasks")
    