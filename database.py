from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, CheckConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from urllib.parse import urlparse

load_dotenv()

# PostgreSQL Configuration
POSTGRES_URL = os.getenv('POSTGRES_URL')
engine = create_engine(POSTGRES_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB = os.getenv('MONGO_DB')

# Parse the MongoDB URI
parsed_uri = urlparse(MONGO_URI)
if parsed_uri.scheme == 'mongodb+srv':
    # For MongoDB Atlas connection
    mongo_client = MongoClient(MONGO_URI)
else:
    # For local MongoDB connection
    mongo_client = MongoClient(MONGO_URI)

# Connect to the existing database
mongo_db = mongo_client.get_database(MONGO_DB)

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'user')", name='check_role'),
    )

class KPI(Base):
    __tablename__ = 'kpis'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    category = Column(String)
    metric_type = Column(String)
    current_value = Column(Float)
    target = Column(Float)
    date = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'))
    
    user = relationship("User")

class MetricValue(Base):
    __tablename__ = 'metric_values'
    
    id = Column(Integer, primary_key=True, index=True)
    kpi_id = Column(Integer, ForeignKey('kpis.id'))
    value = Column(Float, nullable=False)
    date = Column(DateTime, default=datetime.utcnow)
    comment = Column(Text)
    user_id = Column(Integer, ForeignKey('users.id'))
    
    kpi = relationship("KPI")
    user = relationship("User")

# Create all tables
def init_db():
    Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize MongoDB collections and indexes
def init_mongodb():
    try:
        # Check if collections exist, if not create them
        collections = ['kpis', 'kpi_metrics', 'kpi_history', 'programs']
        for collection in collections:
            if collection not in mongo_db.list_collection_names():
                try:
                    mongo_db.create_collection(collection)
                    print(f"Created collection: {collection}")
                except Exception as e:
                    print(f"Warning: Could not create collection {collection}: {str(e)}")

        # Create indexes if they don't exist
        try:
            if 'user_id' not in mongo_db.kpis.index_information():
                mongo_db.kpis.create_index('user_id')
                print("Created index: kpis.user_id")
            if 'kpi_id' not in mongo_db.kpi_metrics.index_information():
                mongo_db.kpi_metrics.create_index('kpi_id')
                print("Created index: kpi_metrics.kpi_id")
            if 'kpi_id_1_date_1' not in mongo_db.kpi_history.index_information():
                mongo_db.kpi_history.create_index([('kpi_id', 1), ('date', 1)])
                print("Created index: kpi_history.kpi_id_1_date_1")
        except Exception as e:
            print(f"Warning: Could not create indexes: {str(e)}")
        
        return True
    except Exception as e:
        print(f"Error initializing MongoDB: {str(e)}")
        return False 