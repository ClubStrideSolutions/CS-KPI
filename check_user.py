import sqlite3

def check_users():
    conn = sqlite3.connect('kpi_platform.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT email, role FROM users")
    users = cursor.fetchall()
    
    print("\nUsers in database:")
    for user in users:
        print(f"Email: {user['email']}, Role: {user['role']}")
    
    cursor.close()
    conn.close()

if __name__ == "__main__":
    check_users() 