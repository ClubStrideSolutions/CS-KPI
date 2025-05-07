import sqlite3
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import bcrypt
from urllib.parse import urlparse
import sys

def load_env():
    """Load environment variables and validate required ones"""
    load_dotenv()
    required_vars = ['ADMIN_EMAIL', 'ADMIN_PASSWORD', 'MONGO_URI', 'MONGO_DB']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please create a .env file with the following variables:")
        print("ADMIN_EMAIL=your_admin_email@example.com")
        print("ADMIN_PASSWORD=your_admin_password")
        print("MONGO_URI=your_mongodb_uri")
        print("MONGO_DB=your_database_name")
        sys.exit(1)

def init_sqlite():
    """Initialize SQLite database and create admin user"""
    try:
        # Connect to SQLite (creates the database if it doesn't exist)
        conn = sqlite3.connect('kpi_platform.db')
        cursor = conn.cursor()

        # Create users table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create admin user if not exists
        admin_email = os.getenv('ADMIN_EMAIL')
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if admin_email and admin_password:
            # Check if admin user exists
            cursor.execute("SELECT * FROM users WHERE email = ?", (admin_email,))
            if not cursor.fetchone():
                hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("""
                    INSERT INTO users (email, password, role)
                    VALUES (?, ?, 'admin')
                """, (admin_email, hashed_password.decode('utf-8')))
                print(f"Created admin user: {admin_email}")
            else:
                print(f"Admin user {admin_email} already exists")

        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Error initializing SQLite database: {str(e)}")
        return False

def init_mongodb():
    """Initialize MongoDB collections and indexes"""
    try:
        # Get MongoDB connection details
        mongo_uri = os.getenv('MONGO_URI')
        mongo_db_name = os.getenv('MONGO_DB')  # Keep the exact case as specified in .env

        # Parse the MongoDB URI
        parsed_uri = urlparse(mongo_uri)
        if parsed_uri.scheme == 'mongodb+srv':
            # For MongoDB Atlas connection
            client = MongoClient(mongo_uri)
        else:
            # For local MongoDB connection
            client = MongoClient(mongo_uri)

        # Connect to the existing database
        db = client.get_database(mongo_db_name)

        # Check if collections exist, if not create them
        collections = ['kpis', 'kpi_metrics', 'kpi_history']
        for collection in collections:
            if collection not in db.list_collection_names():
                try:
                    db.create_collection(collection)
                    print(f"Created collection: {collection}")
                except Exception as e:
                    print(f"Warning: Could not create collection {collection}: {str(e)}")

        # Create indexes if they don't exist
        try:
            if 'user_id' not in db.kpis.index_information():
                db.kpis.create_index('user_id')
                print("Created index: kpis.user_id")
            if 'kpi_id' not in db.kpi_metrics.index_information():
                db.kpi_metrics.create_index('kpi_id')
                print("Created index: kpi_metrics.kpi_id")
            if 'kpi_id_1_date_1' not in db.kpi_history.index_information():
                db.kpi_history.create_index([('kpi_id', 1), ('date', 1)])
                print("Created index: kpi_history.kpi_id_1_date_1")
        except Exception as e:
            print(f"Warning: Could not create indexes: {str(e)}")
        
        return True
    except Exception as e:
        print(f"Error initializing MongoDB: {str(e)}")
        return False

if __name__ == '__main__':
    print("Loading environment variables...")
    load_env()
    
    print("\nInitializing SQLite database...")
    if init_sqlite():
        print("SQLite database initialized successfully!")
    else:
        print("Failed to initialize SQLite database")
        sys.exit(1)
    
    print("\nInitializing MongoDB database...")
    if init_mongodb():
        print("MongoDB database initialized successfully!")
    else:
        print("Failed to initialize MongoDB database")
        sys.exit(1)
    
    print("\nInitialization complete! You can now run the application.") 