from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, CheckConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
import sys
import bcrypt
from dotenv import load_dotenv
from pymongo import MongoClient
from urllib.parse import urlparse

# Load environment variables
load_dotenv()

# Check for required environment variables
def validate_env_vars():
    """Validate that all required environment variables are present"""
    required_vars = ['ADMIN_EMAIL', 'ADMIN_PASSWORD', 'MONGO_URI', 'MONGO_DB', 'DATABASE_URL']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please create a .env file with the following variables:")
        print("ADMIN_EMAIL=your_admin_email@example.com")
        print("ADMIN_PASSWORD=your_admin_password")
        print("DATABASE_URL=your_postgres_connection_string")
        print("MONGO_URI=your_mongodb_uri")
        print("MONGO_DB=your_database_name")
        return False
    return True

# PostgreSQL Configuration using Neon
DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB = os.getenv('MONGO_DB')

# Database connection functions
def get_mongo_connection():
    """Get a MongoDB client connection"""
    try:
        # Parse the MongoDB URI
        parsed_uri = urlparse(MONGO_URI)
        if parsed_uri.scheme == 'mongodb+srv':
            # For MongoDB Atlas connection
            mongo_client = MongoClient(MONGO_URI)
        else:
            # For local MongoDB connection
            mongo_client = MongoClient(MONGO_URI)
        
        # Test the connection
        mongo_client.admin.command('ping')
        
        return mongo_client
    except Exception as e:
        print(f"Error connecting to MongoDB: {str(e)}")
        return None

# Get MongoDB database
def get_mongo_db():
    """Get the MongoDB database"""
    client = get_mongo_connection()
    if client:
        return client.get_database(MONGO_DB)
    return None

# Connect to the MongoDB database
mongo_client = get_mongo_connection()
mongo_db = mongo_client.get_database(MONGO_DB) if mongo_client else None

# SQLAlchemy Models
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

    def __init__(self, email, password, role='user'):
        self.email = email
        self.password = password
        self.role = role

# Initialize databases
def init_postgres():
    """Initialize PostgreSQL database and create admin user"""
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        
        # Create admin user if not exists
        db = SessionLocal()
        admin_email = os.getenv('ADMIN_EMAIL')
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if admin_email and admin_password:
            admin = db.query(User).filter(User.email == admin_email).first()
            if not admin:
                hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
                admin = User(
                    email=admin_email,
                    password=hashed_password.decode('utf-8'),
                    role='admin'
                )
                db.add(admin)
                db.commit()
                print(f"Created admin user: {admin_email}")
            else:
                print(f"Admin user {admin_email} already exists")
        
        db.close()
        return True
    except Exception as e:
        print(f"Error initializing PostgreSQL database: {str(e)}")
        return False

def init_mongodb():
    """Initialize MongoDB collections and indexes"""
    try:
        # Check if mongo_db is valid
        if not mongo_db:
            print("Error: Could not connect to MongoDB")
            return False
            
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
            # Create index information dictionaries
            indexes = {
                'kpis': ['user_id', 'program_id'],
                'kpi_metrics': ['kpi_id', 'date'],
                'kpi_history': [('kpi_id', 1), ('date', 1)]
            }
            
            # Create indexes for kpis collection
            for index in indexes['kpis']:
                index_name = f"{index}_1"
                if index_name not in mongo_db.kpis.index_information():
                    mongo_db.kpis.create_index(index)
                    print(f"Created index: kpis.{index}")
            
            # Create indexes for kpi_metrics collection
            for index in indexes['kpi_metrics']:
                index_name = f"{index}_1"
                if index_name not in mongo_db.kpi_metrics.index_information():
                    mongo_db.kpi_metrics.create_index(index)
                    print(f"Created index: kpi_metrics.{index}")
            
            # Create compound index for kpi_history
            if 'kpi_id_1_date_1' not in mongo_db.kpi_history.index_information():
                mongo_db.kpi_history.create_index(indexes['kpi_history'])
                print("Created index: kpi_history.kpi_id_1_date_1")
            
        except Exception as e:
            print(f"Warning: Could not create indexes: {str(e)}")
        
        return True
    except Exception as e:
        print(f"Error initializing MongoDB: {str(e)}")
        return False

# Initialize databases function
def init_db():
    """Initialize all databases"""
    print("Loading environment variables...")
    if not validate_env_vars():
        return False
    
    print("\nInitializing PostgreSQL database...")
    if not init_postgres():
        print("Failed to initialize PostgreSQL database")
        return False
    
    print("\nInitializing MongoDB database...")
    if not init_mongodb():
        print("Failed to initialize MongoDB database")
        return False
    
    print("\nInitialization complete!")
    return True

# Get database session
def get_db():
    """Get SQLAlchemy database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# If script is run directly, initialize databases
if __name__ == '__main__':
    if init_db():
        print("All databases initialized successfully!")
    else:
        print("Database initialization failed")
        sys.exit(1)