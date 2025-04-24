from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc
from flask_login import login_user, logout_user
import sqlite3
import bcrypt
from app import app, db_path

def login_layout():
    return html.Div([
        dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Login"),
                        dbc.CardBody([
                            dbc.Input(id="login-email", type="email", placeholder="Email", className="mb-3"),
                            dbc.Input(id="login-password", type="password", placeholder="Password", className="mb-3"),
                            dbc.Button("Login", id="login-button", color="primary", className="mb-3"),
                            html.Div(id="login-message"),
                            html.Hr(),
                            html.P("Don't have an account?"),
                            dbc.Button("Register", id="register-button", color="secondary", href="/register")
                        ])
                    ], className="mt-5")
                ], width=6)
            ], justify="center")
        ])
    ])

def register_layout():
    return html.Div([
        dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Register"),
                        dbc.CardBody([
                            dbc.Input(id="register-email", type="email", placeholder="Email", className="mb-3"),
                            dbc.Input(id="register-password", type="password", placeholder="Password", className="mb-3"),
                            dbc.Input(id="register-confirm-password", type="password", placeholder="Confirm Password", className="mb-3"),
                            dbc.Button("Register", id="register-submit-button", color="primary", className="mb-3"),
                            html.Div(id="register-message"),
                            html.Hr(),
                            html.P("Already have an account?"),
                            dbc.Button("Login", id="login-redirect-button", color="secondary", href="/login")
                        ])
                    ], className="mt-5")
                ], width=6)
            ], justify="center")
        ])
    ])

# Callbacks for authentication
@app.callback(
    Output("login-message", "children"),
    [Input("login-button", "n_clicks")],
    [State("login-email", "value"),
     State("login-password", "value")]
)
def login_callback(n_clicks, email, password):
    if n_clicks is None:
        return ""
    
    if not email or not password:
        return dbc.Alert("Please fill in all fields", color="danger")
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            from app import User
            login_user(User(user['id'], user['email'], user['role']))
            return dcc.Location(pathname="/dashboard", id="login-redirect")
        else:
            return dbc.Alert("Invalid email or password", color="danger")
    except Exception as e:
        return dbc.Alert(f"An error occurred: {str(e)}", color="danger")

@app.callback(
    Output("register-message", "children"),
    [Input("register-submit-button", "n_clicks")],
    [State("register-email", "value"),
     State("register-password", "value"),
     State("register-confirm-password", "value")]
)
def register_callback(n_clicks, email, password, confirm_password):
    if n_clicks is None:
        return ""
    
    if not email or not password or not confirm_password:
        return dbc.Alert("Please fill in all fields", color="danger")
    
    if password != confirm_password:
        return dbc.Alert("Passwords do not match", color="danger")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return dbc.Alert("Email already registered", color="danger")
        
        # Hash password and insert new user
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, 'user')",
            (email, hashed_password.decode('utf-8'))
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        return dbc.Alert("Registration successful! Please login.", color="success")
    except Exception as e:
        return dbc.Alert(f"An error occurred: {str(e)}", color="danger") 