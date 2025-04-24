import sqlite3

def update_admin():
    conn = sqlite3.connect('kpi_platform.db')
    cursor = conn.cursor()
    
    # Update the user's role to admin
    cursor.execute("""
        UPDATE users 
        SET role = 'admin' 
        WHERE email = 'admin@clubstride.org'
    """)
    
    # Insert admin user if not exists
    cursor.execute("SELECT * FROM users WHERE email = 'admin@clubstride.org'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (email, password, role)
            VALUES ('admin@clubstride.org', 'dummy_password', 'admin')
        """)
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print("Admin user updated/created successfully!")

if __name__ == "__main__":
    update_admin() 