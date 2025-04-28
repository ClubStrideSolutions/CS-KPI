import os
from dash import Dash, html, dcc, Input, Output, State, no_update
import dash_bootstrap_components as dbc
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, send_from_directory, redirect, url_for, session, request, send_file, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
from dotenv import load_dotenv
import bcrypt
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import wraps
from dash.exceptions import PreventUpdate
import pandas as pd
import io
import plotly.express as px
import plotly.graph_objs as go
from plotly.subplots import make_subplots
from dash.dependencies import ALL
from bson import ObjectId
import dash
import json

# Load environment variables
load_dotenv()

# Initialize Flask app
server = Flask(__name__)
server.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
server.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
server.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy for PostgreSQL
db = SQLAlchemy(server)

# Initialize MongoDB connection
mongo_uri = os.getenv('MONGO_URI')
mongo_db_name = os.getenv('MONGO_DB')
parsed_uri = urlparse(mongo_uri)
if parsed_uri.scheme == 'mongodb+srv':
    mongo_client = MongoClient(mongo_uri)
else:
    mongo_client = MongoClient(mongo_uri)
mongo_db = mongo_client.get_database(mongo_db_name)

# Add custom color scheme
CUSTOM_COLORS = {
    'primary': '#4169E1',  # Royal Blue
    'secondary': '#FFA500',  # Orange
    'success': '#FFA500',  # Using orange instead of default success color
    'info': '#4169E1',     # Blue
    'warning': '#FFB74D',  # Light Orange
    'danger': '#FF6B6B'    # Keep a distinct color for danger
}

# Initialize Dash app with custom theme
app = Dash(__name__, 
           server=server,
           external_stylesheets=[
               dbc.themes.BOOTSTRAP,
               'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css'
           ],
           suppress_callback_exceptions=True)

# Add custom CSS
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            :root {
                --bs-primary: #4169E1;
                --bs-secondary: #FFA500;
                --bs-success: #FFA500;
                --bs-info: #4169E1;
                --bs-warning: #FFB74D;
                --bs-danger: #FF6B6B;
            }
            .btn-primary {
                background-color: #4169E1 !important;
                border-color: #4169E1 !important;
            }
            .btn-success {
                background-color: #FFA500 !important;
                border-color: #FFA500 !important;
            }
            .bg-primary {
                background-color: #4169E1 !important;
            }
            .text-primary {
                color: #4169E1 !important;
            }
            .navbar-dark {
                background-color: #4169E1 !important;
            }
            .card {
                border-color: #4169E1;
            }
            .card-header {
                background-color: #4169E1;
                color: white;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = 'login'

# User class for Flask-Login (using PostgreSQL)
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, email, password, role='user'):
        self.email = email
        self.password = password
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create admin user if not exists
def create_admin_user():
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')
    
    if admin_email and admin_password:
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
            admin = User(
                email=admin_email,
                password=hashed_password.decode('utf-8'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print(f"Created admin user: {admin_email}")

# Create database tables
with server.app_context():
    db.create_all()
    create_admin_user()

# Add login required decorator
def login_required_dash(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Custom styles
CUSTOM_STYLES = {
    'container': {
        'padding': '20px',
        'maxWidth': '1200px',
        'margin': '0 auto'
    },
    'card': {
        'boxShadow': '0 4px 6px rgba(0, 0, 0, 0.1)',
        'borderRadius': '8px',
        'marginBottom': '20px'
    },
    'button': {
        'marginTop': '10px',
        'width': '100%'
    },
    'input': {
        'marginBottom': '15px'
    },
    'alert': {
        'marginBottom': '20px'
    }
}

# Add logout route
@server.route('/logout')
def logout():
    logout_user()
    session.clear()  # Clear the session
    return redirect('/login')

# Main layout
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    dcc.Location(id='_pages_location', refresh=True),
    html.Div(id='navbar-container'),
    # Edit Modal
    dbc.Modal([
        dbc.ModalHeader("Edit KPI"),
        dbc.ModalBody([
            dbc.Input(id="edit-kpi-name", placeholder="KPI Name", className="mb-3"),
            dbc.Input(id="edit-kpi-description", placeholder="Description", className="mb-3"),
            dbc.Input(
                id="edit-kpi-category",
                placeholder="Enter Program Name",
                type="text",
                className="mb-3"
            ),
            dbc.Select(
                id="edit-kpi-metric-type",
                options=[
                    {"label": "Number", "value": "number"},
                    {"label": "Percentage", "value": "percentage"},
                    {"label": "Currency", "value": "currency"},
                    {"label": "Time", "value": "time"}
                ],
                placeholder="Select Metric Type",
                className="mb-3"
            ),
            dbc.Input(id="edit-kpi-target", placeholder="Target Value", type="number", className="mb-3"),
            dbc.Input(id="edit-kpi-id", type="hidden"),
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="edit-modal-close", className="me-2", color="secondary"),
            dbc.Button("Save Changes", id="save-kpi-edit", color="primary"),
        ]),
    ], id="edit-kpi-modal", is_open=False),
    
    # Delete Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader("Delete KPI"),
        dbc.ModalBody("Are you sure you want to delete this KPI? This action cannot be undone."),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="delete-modal-close", className="me-2", color="secondary"),
            dbc.Button("Delete", id="confirm-kpi-delete", color="danger"),
            dbc.Input(id="delete-kpi-id", type="hidden"),
        ]),
    ], id="delete-kpi-modal", is_open=False),

    # Add Update Value Modal
    dbc.Modal([
        dbc.ModalHeader("Update KPI Value"),
        dbc.ModalBody([
            dbc.Input(id="update-kpi-value", type="number", placeholder="New Value", className="mb-3"),
            dbc.Input(id="update-kpi-date", type="date", className="mb-3"),
            dbc.Input(id="update-value-kpi-id", type="hidden"),
            html.Div(id="update-value-kpi-name", className="mb-3"),  # Display KPI name
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="update-value-modal-close", className="me-2", color="secondary"),
            dbc.Button("Save Value", id="save-kpi-value", color="primary"),
        ]),
    ], id="update-value-modal", is_open=False),
    
    html.Div(id='page-content', className='container'),
    dcc.Interval(
        id='interval-component',
        interval=60*1000,  # Update every minute
        n_intervals=0
    )
])

# Callback to update navbar based on login status
@app.callback(
    Output('navbar-container', 'children'),
    [Input('url', 'pathname')]
)
def update_navbar(pathname):
    return create_navbar()

# Callback to update page content based on URL and login status
@app.callback(
    Output("page-content", "children"),
    [Input("url", "pathname")]
)
def render_page_content(pathname):
    if pathname == "/":
        if current_user.is_authenticated:
            return render_kpi_dashboard()
        else:
            return render_login_page()
    elif pathname == "/register":
        if current_user.is_authenticated:
            return html.Div([
                html.H1("Already Logged In"),
                dbc.Alert(f"You are already logged in as {current_user.email}", color="info"),
                dbc.Button("Go to Dashboard", href="/", color="primary")
            ])
        return render_register_page()
    elif pathname == "/login":
        if current_user.is_authenticated:
            return html.Div([
                html.H1("Already Logged In"),
                dbc.Alert(f"You are already logged in as {current_user.email}", color="info"),
                dbc.Button("Go to Dashboard", href="/", color="primary")
            ])
        return render_login_page()
    elif pathname == "/kpis":
        if not current_user.is_authenticated:
            return render_login_page()
        return render_kpi_dashboard()
    elif pathname == "/reports":
        if not current_user.is_authenticated:
            return render_login_page()
        return render_reports_page()
    elif pathname == "/programs-page":
        if not current_user.is_authenticated or current_user.role != 'admin':
            return html.Div([
                html.H1("Access Denied"),
                dbc.Alert("This page is only accessible to administrators", color="danger"),
                dbc.Button("Return to Dashboard", href="/", color="primary"),
            ])
        return render_program_management()
    else:
        return html.Div([
            html.H1("404: Not found", className="text-danger"),
            html.P(f"The pathname {pathname} was not recognized..."),
            dbc.Button("Return to Home", href="/", color="primary")
        ])

# Update the registration callback
@app.callback(
    [Output("register-message", "children"),
     Output("_pages_location", "pathname", allow_duplicate=True)],
    [Input("register-button", "n_clicks")],
    [State("register-email", "value"),
     State("register-password", "value"),
     State("register-confirm-password", "value")],
    prevent_initial_call=True
)
def register_user(n_clicks, email, password, confirm_password):
    if n_clicks is None:
        raise PreventUpdate
    
    if not email or not password or not confirm_password:
        return html.Div("Please fill in all fields", className="text-danger"), no_update
    
    if password != confirm_password:
        return html.Div("Passwords do not match", className="text-danger"), no_update
    
    if len(password) < 8:
        return html.Div("Password must be at least 8 characters long", className="text-danger"), no_update
    
    try:
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return html.Div("Email already registered", className="text-danger"), no_update
        
        # Hash password and create user
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(
            email=email,
            password=hashed_password.decode('utf-8'),
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()
        
        return html.Div("Registration successful! Redirecting to login...", className="text-success"), "/login"
    
    except Exception as e:
        print(f"Error during registration: {str(e)}")
        return html.Div(f"Registration failed: {str(e)}", className="text-danger"), no_update

# Update the login callback
@app.callback(
    [Output("login-message", "children"),
     Output("_pages_location", "pathname")],
    [Input("login-button", "n_clicks")],
    [State("login-email", "value"),
     State("login-password", "value")],
    prevent_initial_call=True
)
def login_callback(n_clicks, email, password):
    if n_clicks is None:
        raise PreventUpdate
    
    if not email or not password:
        return html.Div("Please fill in all fields", className="text-danger"), no_update
    
    try:
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            session['user_email'] = user.email
            session['user_role'] = user.role
            return html.Div("Login successful! Redirecting...", className="text-success"), "/"
        else:
            return html.Div("Invalid email or password", className="text-danger"), no_update
    except Exception as e:
        print(f"Login error: {str(e)}")
        return html.Div(f"Error during login: {str(e)}", className="text-danger"), no_update

# Callback for creating KPIs
@app.callback(
    [Output("kpi-message", "children"),
     Output("kpi-name", "value"),
     Output("kpi-description", "value"),
     Output("kpi-category", "value"),
     Output("kpi-metric-type", "value"),
     Output("kpi-current-value", "value"),
     Output("kpi-target", "value"),
     Output("kpi-date", "value")],
    [Input("create-kpi-button", "n_clicks")],
    [State("kpi-name", "value"),
     State("kpi-description", "value"),
     State("kpi-category", "value"),
     State("kpi-metric-type", "value"),
     State("kpi-current-value", "value"),
     State("kpi-target", "value"),
     State("kpi-date", "value")]
)
def create_kpi(n_clicks, name, description, category, metric_type, current_value, target, date):
    if n_clicks is None:
        raise PreventUpdate
    
    if not all([name, description, category, metric_type, current_value, target, date]):
        return (
            html.Div("Please fill in all fields", className="text-danger"),
            no_update, no_update, no_update, no_update, no_update, no_update, no_update
        )
    
    try:
        # Verify the program exists
        program = mongo_db.programs.find_one({"name": category})
        if not program:
            return (
                html.Div("Selected program does not exist", className="text-danger"),
                no_update, no_update, no_update, no_update, no_update, no_update, no_update
            )
        
        # Create KPI document
        kpi_data = {
            "name": name,
            "description": description,
            "category": category,
            "program_id": program["_id"],
            "metric_type": metric_type,
            "target": float(target),
            "created_at": datetime.now(),
            "user_id": current_user.id
        }
        
        # Insert KPI
        kpi_result = mongo_db.kpis.insert_one(kpi_data)
        
        if kpi_result.inserted_id:
            # Create initial metric
            metric_data = {
                "kpi_id": str(kpi_result.inserted_id),
                "user_id": current_user.id,
                "value": float(current_value),
                "date": datetime.strptime(date, "%Y-%m-%d")
            }
            mongo_db.kpi_metrics.insert_one(metric_data)
            
            # Create initial history entry
            history_data = {
                "kpi_id": str(kpi_result.inserted_id),
                "user_id": current_user.id,
                "kpi_name": name,
                "action": "create",
                "comment": f"KPI created with initial value: {current_value} and target: {target}",
                "date": datetime.now()
            }
            mongo_db.kpi_history.insert_one(history_data)
            
            return (
                html.Div("KPI created successfully!", className="text-success"),
                "",  # Clear name
                "",  # Clear description
                "",  # Clear category
                "",  # Clear metric type
                "",  # Clear current value
                "",  # Clear target
                datetime.now().strftime("%Y-%m-%d")  # Reset date to today
            )
        else:
            return (
                html.Div("Failed to create KPI", className="text-danger"),
                no_update, no_update, no_update, no_update, no_update, no_update, no_update
            )
    except Exception as e:
        print(f"Error creating KPI: {str(e)}")
        return (
            html.Div(f"Error: {str(e)}", className="text-danger"),
            no_update, no_update, no_update, no_update, no_update, no_update, no_update
        )

# Update the KPI list callback to handle all updates
@app.callback(
    Output("kpi-list", "children"),
    [Input("create-kpi-button", "n_clicks"),
     Input("save-kpi-edit", "n_clicks"),
     Input("confirm-kpi-delete", "n_clicks"),
     Input("save-kpi-value", "n_clicks")],
    [State("edit-kpi-id", "value"),
     State("edit-kpi-name", "value"),
     State("edit-kpi-description", "value"),
     State("edit-kpi-category", "value"),
     State("edit-kpi-target", "value"),
     State("delete-kpi-id", "value"),
     State("update-value-kpi-id", "value"),
     State("update-kpi-value", "value"),
     State("update-kpi-date", "value")]
)
def update_kpi_list(create_clicks, edit_clicks, delete_clicks, update_value_clicks,
                    edit_id, name, description, category, target,
                    delete_id, update_id, new_value, update_date):
    ctx = dash.callback_context
    
    try:
        if ctx.triggered:
            trigger_id = ctx.triggered[0]["prop_id"]
            
            # Handle KPI edit
            if trigger_id == "save-kpi-edit.n_clicks" and edit_clicks:
                if edit_id and name and description and category and target:
                    mongo_db.kpis.update_one(
                        {"_id": ObjectId(edit_id)},
                        {
                            "$set": {
                                "name": name,
                                "description": description,
                                "category": category,
                                "target": float(target),
                                "updated_at": datetime.now()
                            }
                        }
                    )
                    # Add to history
                    mongo_db.kpi_history.insert_one({
                        "kpi_id": edit_id,
                        "user_id": current_user.id,
                        "kpi_name": name,
                        "action": "update",
                        "comment": f"KPI updated with new target: {target}",
                        "date": datetime.now()
                    })
            
            # Handle KPI delete
            elif trigger_id == "confirm-kpi-delete.n_clicks" and delete_clicks:
                if delete_id:
                    mongo_db.kpis.delete_one({"_id": ObjectId(delete_id)})
                    mongo_db.kpi_metrics.delete_many({"kpi_id": delete_id})
                    mongo_db.kpi_history.delete_many({"kpi_id": delete_id})
            
            # Handle KPI value update
            elif trigger_id == "save-kpi-value.n_clicks" and update_value_clicks:
                if update_id and new_value and update_date:
                    # Insert new metric value
                    metric_data = {
                        "kpi_id": update_id,
                        "user_id": current_user.id,
                        "value": float(new_value),
                        "date": datetime.strptime(update_date, "%Y-%m-%d")
                    }
                    mongo_db.kpi_metrics.insert_one(metric_data)
                    
                    # Add to history
                    kpi = mongo_db.kpis.find_one({"_id": ObjectId(update_id)})
                    if kpi:
                        history_data = {
                            "kpi_id": update_id,
                            "user_id": current_user.id,
                            "kpi_name": kpi["name"],
                            "action": "update",
                            "comment": f"Updated value to {new_value}",
                            "date": datetime.now()
                        }
                        mongo_db.kpi_history.insert_one(history_data)
        
        # Get all KPIs for the current user
        if not current_user.is_authenticated:
            return html.Div("Please login to view KPIs")
        
        kpis = list(mongo_db.kpis.find({"user_id": current_user.id}))
        
        if not kpis:
            return html.Div([
                html.H4("No KPIs found"),
                html.P("Create your first KPI using the form on the left.")
            ])
        
        # Create KPI table
        return dbc.Card([
            dbc.CardHeader(html.H4("Your KPIs", className="mb-0")),
            dbc.CardBody([
                dbc.Table(
                    [
                        html.Thead([
                            html.Tr([
                                html.Th("Name"),
                                html.Th("Program"),
                                html.Th("Metric Type"),
                                html.Th("Current Value"),
                                html.Th("Target"),
                                html.Th("Last Updated"),
                                html.Th("Actions")
                            ])
                        ]),
                        html.Tbody([
                            html.Tr([
                                html.Td(kpi.get("name", "N/A")),
                                html.Td(kpi.get("category", "N/A")),
                                html.Td(kpi.get("metric_type", "N/A")),
                                html.Td(get_latest_metric_value(str(kpi["_id"]))),
                                html.Td(kpi.get("target", "N/A")),
                                html.Td(get_latest_metric_date(str(kpi["_id"]))),
                                html.Td([
                                    dbc.Button(
                                        html.I(className="fas fa-chart-line"),
                                        color="success",  # This will now use orange
                                        size="sm",
                                        className="me-2",
                                        id={"type": "update-value", "index": str(kpi["_id"])}
                                    ),
                                    dbc.Button(
                                        html.I(className="fas fa-edit"),
                                        color="primary",  # This will now use blue
                                        size="sm",
                                        className="me-2",
                                        id={"type": "edit-kpi", "index": str(kpi["_id"])}
                                    ),
                                    dbc.Button(
                                        html.I(className="fas fa-trash"),
                                        color="danger",
                                        size="sm",
                                        id={"type": "delete-kpi", "index": str(kpi["_id"])}
                                    )
                                ])
                            ]) for kpi in kpis
                        ])
                    ],
                    bordered=True,
                    hover=True,
                    responsive=True,
                    className="mb-0"
                )
            ])
        ])
    except Exception as e:
        print(f"Error updating KPI list: {str(e)}")
        return html.Div(f"Error: {str(e)}", className="text-danger")

# Add callbacks for modal functionality
@app.callback(
    [Output("edit-kpi-modal", "is_open"),
     Output("edit-kpi-name", "value"),
     Output("edit-kpi-description", "value"),
     Output("edit-kpi-category", "value"),
     Output("edit-kpi-metric-type", "value"),
     Output("edit-kpi-target", "value"),
     Output("edit-kpi-id", "value")],
    [Input({"type": "edit-kpi", "index": ALL}, "n_clicks"),
     Input("edit-modal-close", "n_clicks"),
     Input("save-kpi-edit", "n_clicks")],
    [State("edit-kpi-modal", "is_open")]
)
def toggle_edit_modal(edit_clicks, close_click, save_click, is_open):
    ctx = dash.callback_context
    if not ctx.triggered:
        return False, "", "", "", "", "", ""
    
    trigger_id = ctx.triggered[0]["prop_id"]
    
    if trigger_id == "edit-modal-close.n_clicks" or trigger_id == "save-kpi-edit.n_clicks":
        return False, "", "", "", "", "", ""
    
    if not any(edit_clicks):
        raise PreventUpdate
    
    # Find which edit button was clicked
    for i, clicks in enumerate(edit_clicks):
        if clicks:
            # Get the KPI ID from the button's index
            kpi_id = ctx.inputs_list[0][i]["id"]["index"]
            # Fetch KPI data from MongoDB
            kpi = mongo_db.kpis.find_one({"_id": ObjectId(kpi_id)})
            if kpi:
                return True, kpi.get("name", ""), kpi.get("description", ""), kpi.get("category", ""), kpi.get("metric_type", ""), kpi.get("target", ""), kpi_id
    
    raise PreventUpdate

@app.callback(
    [Output("delete-kpi-modal", "is_open"),
     Output("delete-kpi-id", "value")],
    [Input({"type": "delete-kpi", "index": ALL}, "n_clicks"),
     Input("delete-modal-close", "n_clicks"),
     Input("confirm-kpi-delete", "n_clicks")],
    [State("delete-kpi-modal", "is_open")]
)
def toggle_delete_modal(delete_clicks, close_click, confirm_click, is_open):
    ctx = dash.callback_context
    if not ctx.triggered:
        return False, ""
    
    trigger_id = ctx.triggered[0]["prop_id"]
    
    if trigger_id == "delete-modal-close.n_clicks":
        return False, ""
    
    if trigger_id == "confirm-kpi-delete.n_clicks":
        return False, ""
    
    if not any(delete_clicks):
        raise PreventUpdate
    
    # Find which delete button was clicked
    for i, clicks in enumerate(delete_clicks):
        if clicks:
            kpi_id = ctx.inputs_list[0][i]["id"]["index"]
            return True, kpi_id
    
    raise PreventUpdate

def get_latest_metric_value(kpi_id):
    """Helper function to get the latest metric value for a KPI"""
    try:
        latest_metric = mongo_db.kpi_metrics.find_one(
            {"kpi_id": kpi_id},
            sort=[("date", -1)]
        )
        return latest_metric["value"] if latest_metric else "No data"
    except Exception as e:
        print(f"Error getting metric value: {str(e)}")
        return "Error"

def get_latest_metric_date(kpi_id):
    """Helper function to get the latest metric date for a KPI"""
    try:
        latest_metric = mongo_db.kpi_metrics.find_one(
            {"kpi_id": kpi_id},
            sort=[("date", -1)]
        )
        return latest_metric["date"].strftime("%Y-%m-%d") if latest_metric else "N/A"
    except Exception as e:
        print(f"Error getting metric date: {str(e)}")
        return "Error"

# Add callback to update charts based on selection
@app.callback(
    Output("charts-container", "children"),
    [Input("chart-selector", "value"),
     Input("time-range", "value"),
     Input("refresh-charts", "n_clicks")]
)
def update_charts(selected_charts, time_range, n_clicks):
    if not current_user.is_authenticated or not selected_charts:
        raise PreventUpdate
    
    try:
        charts = []
        
        # Calculate date range
        end_date = datetime.now()
        if time_range == "7d":
            start_date = end_date - timedelta(days=7)
        elif time_range == "30d":
            start_date = end_date - timedelta(days=30)
        elif time_range == "90d":
            start_date = end_date - timedelta(days=90)
        elif time_range == "ytd":
            start_date = datetime(end_date.year, 1, 1)
        else:  # all time
            start_date = datetime(2000, 1, 1)  # arbitrary past date
        
        # Get KPI data
        kpis = list(mongo_db.kpis.find({"user_id": current_user.id}))
        metrics = list(mongo_db.kpi_metrics.find({
            "user_id": current_user.id,
            "date": {"$gte": start_date, "$lte": end_date}
        }))
        
        if not kpis:
            return html.Div("No KPIs found. Create your first KPI to see visualizations.", className="text-muted")
        
        # Convert to pandas for easier manipulation
        df_metrics = pd.DataFrame(metrics)
        if not df_metrics.empty:
            df_metrics['date'] = pd.to_datetime(df_metrics['date'])
        
        chart_rows = []
        current_row = []
        
        for chart_type in selected_charts:
            if chart_type == "performance":
                if not df_metrics.empty:
                    fig = go.Figure()
                    for kpi in kpis:
                        kpi_metrics = df_metrics[df_metrics['kpi_id'] == str(kpi['_id'])]
                        if not kpi_metrics.empty:
                            fig.add_trace(go.Scatter(
                                x=kpi_metrics['date'],
                                y=kpi_metrics['value'],
                                name=kpi['name'],
                                mode='lines+markers'
                            ))
                    fig.update_layout(
                        title='Performance Over Time',
                        height=400,
                        margin=dict(l=40, r=40, t=40, b=40)
                    )
                    current_row.append(dbc.Col(dcc.Graph(figure=fig), width=6))
            
            elif chart_type == "target":
                if not df_metrics.empty:
                    fig = go.Figure()
                    for kpi in kpis:
                        kpi_metrics = df_metrics[df_metrics['kpi_id'] == str(kpi['_id'])]
                        if not kpi_metrics.empty:
                            fig.add_trace(go.Scatter(
                                x=kpi_metrics['date'],
                                y=kpi_metrics['value'],
                                name=f"{kpi['name']} (Actual)",
                                line=dict(color='blue')
                            ))
                            fig.add_trace(go.Scatter(
                                x=kpi_metrics['date'],
                                y=[kpi['target']] * len(kpi_metrics),
                                name=f"{kpi['name']} (Target)",
                                line=dict(dash='dash', color='red')
                            ))
                    fig.update_layout(
                        title='Target vs Actual',
                        height=400,
                        margin=dict(l=40, r=40, t=40, b=40)
                    )
                    current_row.append(dbc.Col(dcc.Graph(figure=fig), width=6))
            
            elif chart_type == "category":
                if kpis:
                    category_counts = pd.DataFrame(kpis)['category'].value_counts()
                    fig = px.pie(
                        values=category_counts.values,
                        names=category_counts.index,
                        title='KPIs by Category',
                        hole=0.4
                    )
                    fig.update_layout(
                        height=400,
                        margin=dict(l=40, r=40, t=40, b=40)
                    )
                    current_row.append(dbc.Col(dcc.Graph(figure=fig), width=6))
            
            elif chart_type == "gauges":
                gauge_row = []
                for kpi in kpis:
                    if len(gauge_row) == 2:
                        chart_rows.append(dbc.Row(gauge_row, className="mb-4"))
                        gauge_row = []
                    
                    latest_value = get_latest_metric_value(str(kpi['_id']))
                    try:
                        value = float(latest_value)
                    except:
                        value = 0
                    
                    fig = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=value,
                        title={'text': kpi['name']},
                        gauge={
                            'axis': {'range': [0, float(kpi['target']) * 1.2]},
                            'threshold': {
                                'line': {'color': "red", 'width': 4},
                                'thickness': 0.75,
                                'value': float(kpi['target'])
                            }
                        }
                    ))
                    fig.update_layout(height=250)
                    gauge_row.append(dbc.Col(dcc.Graph(figure=fig), width=6))
                
                if gauge_row:
                    chart_rows.append(dbc.Row(gauge_row, className="mb-4"))
            
            elif chart_type == "trends":
                if not df_metrics.empty:
                    df_metrics['month'] = df_metrics['date'].dt.to_period('M')
                    monthly_avg = df_metrics.groupby(['month', 'kpi_id'])['value'].mean().reset_index()
                    fig = go.Figure()
                    for kpi in kpis:
                        kpi_data = monthly_avg[monthly_avg['kpi_id'] == str(kpi['_id'])]
                        if not kpi_data.empty:
                            fig.add_trace(go.Scatter(
                                x=kpi_data['month'].astype(str),
                                y=kpi_data['value'],
                                name=kpi['name'],
                                mode='lines+markers'
                            ))
                    fig.update_layout(
                        title='Monthly Trends',
                        height=400,
                        margin=dict(l=40, r=40, t=40, b=40)
                    )
                    current_row.append(dbc.Col(dcc.Graph(figure=fig), width=6))
            
            elif chart_type == "achievement":
                if not df_metrics.empty:
                    achievement_data = []
                    for kpi in kpis:
                        latest_value = float(get_latest_metric_value(str(kpi['_id'])))
                        target = float(kpi['target'])
                        achievement_rate = (latest_value / target * 100) if target != 0 else 0
                        achievement_data.append({
                            'KPI': kpi['name'],
                            'Achievement Rate': achievement_rate
                        })
                    
                    df_achievement = pd.DataFrame(achievement_data)
                    fig = go.Figure(go.Bar(
                        x=df_achievement['KPI'],
                        y=df_achievement['Achievement Rate'],
                        text=df_achievement['Achievement Rate'].round(1).astype(str) + '%',
                        textposition='auto',
                    ))
                    fig.update_layout(
                        title='Achievement Rate (%)',
                        height=400,
                        margin=dict(l=40, r=40, t=40, b=40),
                        yaxis_range=[0, 120]
                    )
                    current_row.append(dbc.Col(dcc.Graph(figure=fig), width=6))
            
            # Add row to chart_rows when it has 2 charts or is the last chart
            if len(current_row) == 2 or chart_type == selected_charts[-1]:
                chart_rows.append(dbc.Row(current_row, className="mb-4"))
                current_row = []
        
        return html.Div(chart_rows)
    
    except Exception as e:
        print(f"Error updating charts: {str(e)}")
        return html.Div(f"Error loading charts: {str(e)}", className="text-danger")

# Add the Excel download route and update the reports page functionality
@app.server.route('/download_excel')
@login_required
def download_excel():
    try:
        # Get query parameters
        report_type = request.args.get('type', 'kpi')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if not all([start_date, end_date]):
            return "Please select date range", 400
        
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
        end_date = datetime.strptime(end_date, "%Y-%m-%d")
        
        # Create Excel file in memory
        output = io.BytesIO()
        
        if report_type == "kpi":
            # Get KPI data
            kpis = list(mongo_db.kpis.find({"user_id": current_user.id}))
            data = []
            for kpi in kpis:
                metrics = list(mongo_db.kpi_metrics.find({
                    "kpi_id": str(kpi["_id"]),
                    "date": {"$gte": start_date, "$lte": end_date}
                }).sort("date", 1))
                
                for metric in metrics:
                    data.append({
                        "KPI Name": kpi["name"],
                        "Program": kpi.get("category", "N/A"),
                        "Metric Type": kpi.get("metric_type", "N/A"),
                        "Value": metric["value"],
                        "Target": kpi["target"],
                        "Date": metric["date"].strftime("%Y-%m-%d"),
                        "Status": "On Target" if float(metric["value"]) >= float(kpi["target"]) else "Off Target"
                    })
            
            df = pd.DataFrame(data)
            
        elif report_type == "user":
            # Get user activity data
            activities = list(mongo_db.kpi_history.find({
                "user_id": current_user.id,
                "date": {"$gte": start_date, "$lte": end_date}
            }).sort("date", 1))
            
            data = [{
                "Date": activity["date"].strftime("%Y-%m-%d %H:%M"),
                "Action": activity.get("action", "N/A"),
                "Comment": activity.get("comment", "N/A")
            } for activity in activities]
            
            df = pd.DataFrame(data)
            
        else:  # system report
            data = [{
                "Report Period": f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
                "Status": "System Operating Normally",
                "Total KPIs": mongo_db.kpis.count_documents({"user_id": current_user.id}),
                "Total Metrics": mongo_db.kpi_metrics.count_documents({"user_id": current_user.id})
            }]
            df = pd.DataFrame(data)
        
        # Write to Excel
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Report', index=False)
            
            # Auto-adjust columns' width
            worksheet = writer.sheets['Report']
            for idx, col in enumerate(df.columns):
                series = df[col]
                max_len = max(
                    series.astype(str).map(len).max(),
                    len(str(series.name))
                ) + 1
                worksheet.set_column(idx, idx, max_len)
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'kpi_report_{datetime.now().strftime("%Y%m%d")}.xlsx'
        )
        
    except Exception as e:
        print(f"Error generating Excel: {str(e)}")
        return str(e), 500

# Update the reports page to handle Excel downloads
def render_reports_page():
    if not current_user.is_authenticated:
        return html.Div([
            html.H1("Access Denied"),
            dbc.Alert("Please log in to view reports", color="danger"),
            dbc.Button("Login", href="/login", color="primary"),
        ])

    return html.Div([
        html.H1([
            html.I(className="fas fa-file-alt me-2"),
            "KPI Reports"
        ], className="mb-4"),
        
        dbc.Card([
            dbc.CardHeader("Report Filters"),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.Label("Report Type"),
                        dcc.Dropdown(
                            id='report-type',
                            options=[
                                {'label': 'All Programs', 'value': 'all'},
                                {'label': 'By Program', 'value': 'program'},
                                {'label': 'By User', 'value': 'user'}
                            ],
                            value='all',
                            className="mb-3"
                        )
                    ], width=3),
                    dbc.Col([
                        html.Label("Program"),
                        dcc.Dropdown(
                            id='program-filter',
                            options=[],  # Will be populated by callback
                            className="mb-3",
                            disabled=True
                        )
                    ], width=3),
                    dbc.Col([
                        html.Label("User"),
                        dcc.Dropdown(
                            id='user-filter',
                            options=[],  # Will be populated by callback
                            className="mb-3",
                            disabled=True
                        )
                    ], width=3),
                    dbc.Col([
                        html.Label("Date Range"),
                        dcc.DatePickerRange(
                            id='date-range',
                            start_date=datetime.now().date().replace(day=1).strftime("%Y-%m-%d"),
                            end_date=datetime.now().date().strftime("%Y-%m-%d"),
                            className="mb-3"
                        )
                    ], width=3)
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Button([
                            html.I(className="fas fa-sync-alt me-2"),
                            "Generate Report"
                        ], id="generate-report", color="primary", className="me-2"),
                        dbc.Button([
                            html.I(className="fas fa-file-excel me-2"),
                            "Export to Excel"
                        ], id="export-excel", color="success")
                    ])
                ])
            ])
        ], className="mb-4"),
        
        dbc.Spinner(
            html.Div(id="report-content", className="table-responsive")
        ),
        
        # Add a hidden div for storing the download data
        html.Div(id="download-container", style={"display": "none"}),
        dcc.Download(id="download-dataframe-xlsx")
    ])

@app.callback(
    [Output("program-filter", "options"),
     Output("program-filter", "disabled"),
     Output("user-filter", "options"),
     Output("user-filter", "disabled")],
    [Input("report-type", "value")]
)
def update_report_filters(report_type):
    if not report_type:
        raise PreventUpdate
        
    program_options = []
    user_options = []
    
    try:
        if report_type == "program":
            programs = list(mongo_db.programs.find())
            program_options = [{"label": p["name"], "value": str(p["_id"])} for p in programs]
            return program_options, False, [], True
        elif report_type == "user":
            users = list(mongo_db.users.find())
            user_options = [{"label": u["email"], "value": str(u["_id"])} for u in users]
            return [], True, user_options, False
        else:
            return [], True, [], True
    except Exception as e:
        print(f"Error updating filters: {str(e)}")
        return [], True, [], True

@app.callback(
    Output("report-content", "children"),
    [Input("generate-report", "n_clicks")],
    [State("report-type", "value"),
     State("program-filter", "value"),
     State("user-filter", "value"),
     State("date-range", "start_date"),
     State("date-range", "end_date")]
)
def generate_report(n_clicks, report_type, program_id, user_id, start_date, end_date):
    if not n_clicks:
        return html.Div("Click 'Generate Report' to view the data", className="text-muted")
    
    try:
        # Convert string dates to datetime objects
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
        end_date = datetime.strptime(end_date, "%Y-%m-%d")
        
        # Build query based on filters
        query = {
            "created_at": {
                "$gte": start_date,
                "$lte": end_date + timedelta(days=1)
            }
        }
        
        if report_type == "program" and program_id:
            query["program_id"] = ObjectId(program_id)
        elif report_type == "user" and user_id:
            query["user_id"] = ObjectId(user_id)
        
        # Get KPIs and their latest metrics
        kpis = list(mongo_db.kpis.find(query))
        
        if not kpis:
            return html.Div("No data found for the selected filters", className="text-muted")
        
        # Create report table
        return dbc.Table([
            html.Thead([
                html.Tr([
                    html.Th("Project Name"),
                    html.Th("KPI"),
                    html.Th("Description"),
                    html.Th("Target"),
                    html.Th("Current Status"),
                    html.Th("Progress/Comments"),
                    html.Th("Owner"),
                    html.Th("Review Frequency")
                ])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(get_program_name(kpi.get("program_id"))),
                    html.Td(kpi["name"]),
                    html.Td(kpi.get("description", "N/A")),
                    html.Td(kpi.get("target", "N/A")),
                    html.Td(get_latest_metric(kpi["_id"])),
                    html.Td(get_latest_comment(kpi["_id"])),
                    html.Td(get_owner_name(kpi.get("user_id"))),
                    html.Td(kpi.get("review_frequency", "Monthly"))
                ]) for kpi in kpis
            ])
        ], bordered=True, hover=True, responsive=True)
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return html.Div(f"Error generating report: {str(e)}", className="text-danger")

@app.callback(
    Output("download-dataframe-xlsx", "data"),
    [Input("export-excel", "n_clicks")],
    [State("report-content", "children"),
     State("date-range", "start_date"),
     State("date-range", "end_date")]
)
def export_report(n_clicks, report_content, start_date, end_date):
    if not n_clicks or not report_content:
        raise PreventUpdate
    
    try:
        # Convert the report data to a pandas DataFrame
        data = []
        for row in report_content["props"]["children"][1]["props"]["children"]:
            cells = row["props"]["children"]
            data.append({
                "Project Name": cells[0]["props"]["children"],
                "KPI": cells[1]["props"]["children"],
                "Description": cells[2]["props"]["children"],
                "Target": cells[3]["props"]["children"],
                "Current Status": cells[4]["props"]["children"],
                "Progress/Comments": cells[5]["props"]["children"],
                "Owner": cells[6]["props"]["children"],
                "Review Frequency": cells[7]["props"]["children"]
            })
        
        df = pd.DataFrame(data)
        
        return dcc.send_data_frame(
            df.to_excel,
            filename=f"kpi_report_{datetime.now().strftime('%Y%m%d')}.xlsx",
            sheet_name="KPI Report",
            index=False
        )
    except Exception as e:
        print(f"Error exporting report: {str(e)}")
        raise PreventUpdate

# Add program management page
def render_program_management():
    if not current_user.is_authenticated or current_user.role != 'admin':
        return html.Div([
            html.H1("Access Denied"),
            dbc.Alert("This page is only accessible to administrators", color="danger"),
            dbc.Button("Return to Dashboard", href="/", color="primary"),
        ])
    
    return html.Div([
        html.H1([
            html.I(className="fas fa-sitemap me-2"),
            "Program Management"
        ], className="mb-4"),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Create New Program"),
                    dbc.CardBody([
                        dbc.Input(
                            id="program-name",
                            placeholder="Program Name",
                            className="mb-3"
                        ),
                        dbc.Textarea(
                            id="program-description",
                            placeholder="Program Description",
                            className="mb-3"
                        ),
                        dbc.Button([
                            html.I(className="fas fa-plus me-2"),
                            "Create Program"
                        ], id="create-program-button", color="primary")
                    ])
                ])
            ], width=4),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Existing Programs"),
                    dbc.CardBody([
                        html.Div(id="program-list", className="table-responsive")
                    ])
                ])
            ], width=8)
        ]),
        
        # Add Edit Program Modal
        dbc.Modal([
            dbc.ModalHeader("Edit Program"),
            dbc.ModalBody([
                dbc.Input(
                    id="edit-program-name",
                    placeholder="Program Name",
                    className="mb-3"
                ),
                dbc.Textarea(
                    id="edit-program-description",
                    placeholder="Program Description",
                    className="mb-3"
                ),
                dbc.Input(
                    id="edit-program-id",
                    type="hidden"
                )
            ]),
            dbc.ModalFooter([
                dbc.Button("Cancel", id="edit-program-close", className="me-2", color="secondary"),
                dbc.Button("Save Changes", id="save-program-edit", color="primary")
            ])
        ], id="edit-program-modal", is_open=False)
    ])

# Add program management callbacks
@app.callback(
    [Output("program-list", "children"),
     Output("program-name", "value"),
     Output("program-description", "value")],
    [Input("create-program-button", "n_clicks"),
     Input("save-program-edit", "n_clicks")],
    [State("program-name", "value"),
     State("program-description", "value"),
     State("edit-program-name", "value"),
     State("edit-program-description", "value"),
     State("edit-program-id", "value")]
)
def manage_programs(create_clicks, edit_clicks, name, description, edit_name, edit_description, edit_id):
    ctx = dash.callback_context
    if not ctx.triggered:
        # Initial load - just display existing programs
        programs = list(mongo_db.programs.find().sort('created_at', -1))
        return create_program_table(programs), "", ""
    
    trigger_id = ctx.triggered[0]["prop_id"]
    
    if "create-program-button" in trigger_id and create_clicks:
        if name:
            # Check if program with same name exists
            existing = mongo_db.programs.find_one({'name': name})
            if existing:
                return create_program_table(list(mongo_db.programs.find().sort('created_at', -1))), name, description
            
            # Create new program
            program = {
                'name': name,
                'description': description,
                'created_by': current_user.id,
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            mongo_db.programs.insert_one(program)
            
    elif "save-program-edit" in trigger_id and edit_clicks:
        if edit_id and edit_name:
            # Check if another program with same name exists
            existing = mongo_db.programs.find_one({
                'name': edit_name,
                '_id': {'$ne': ObjectId(edit_id)}
            })
            if existing:
                return create_program_table(list(mongo_db.programs.find().sort('created_at', -1))), "", ""
            
            update = {
                'name': edit_name,
                'description': edit_description,
                'updated_at': datetime.now()
            }
            mongo_db.programs.update_one(
                {'_id': ObjectId(edit_id)},
                {'$set': update}
            )
    
    # Return updated program list
    programs = list(mongo_db.programs.find().sort('created_at', -1))
    return create_program_table(programs), "", ""

def create_program_table(programs):
    """Create a table displaying existing programs"""
    if not programs:
        return html.Div("No programs found", className="text-muted")
    
    return dbc.Table([
        html.Thead([
            html.Tr([
                html.Th("Program Name"),
                html.Th("Description"),
                html.Th("Created"),
                html.Th("Actions")
            ])
        ]),
        html.Tbody([
            html.Tr([
                html.Td(program["name"]),
                html.Td(program.get("description", "N/A")),
                html.Td(program["created_at"].strftime("%Y-%m-%d")),
                html.Td([
                    dbc.Button(
                        html.I(className="fas fa-edit"),
                        id={"type": "edit-program", "index": str(program["_id"])},
                        color="primary",
                        size="sm",
                        className="me-2"
                    ),
                    dbc.Button(
                        html.I(className="fas fa-trash"),
                        id={"type": "delete-program", "index": str(program["_id"])},
                        color="danger",
                        size="sm",
                        className="me-2"
                    )
                ])
            ]) for program in programs
        ])
    ], bordered=True, hover=True, responsive=True, className="mb-0")

def get_program_name(program_id):
    """Helper function to get program name from ID"""
    if not program_id:
        return "N/A"
    try:
        program = mongo_db.programs.find_one({"_id": ObjectId(program_id)})
        return program["name"] if program else "N/A"
    except Exception as e:
        print(f"Error getting program name: {str(e)}")
        return "N/A"

def get_latest_metric(kpi_id):
    """Helper function to get latest metric value and status"""
    try:
        latest_metric = mongo_db.kpi_metrics.find_one(
            {"kpi_id": str(kpi_id)},
            sort=[("date", -1)]
        )
        if not latest_metric:
            return "No data"
        
        kpi = mongo_db.kpis.find_one({"_id": ObjectId(kpi_id)})
        if not kpi:
            return "No KPI found"
        
        value = latest_metric["value"]
        target = kpi.get("target", 0)
        
        status = "On Target" if value >= target else "Off Target"
        return f"{value} ({status})"
    except Exception as e:
        print(f"Error getting latest metric: {str(e)}")
        return "Error"

def get_latest_comment(kpi_id):
    """Helper function to get latest comment from history"""
    try:
        latest_history = mongo_db.kpi_history.find_one(
            {"kpi_id": str(kpi_id)},
            sort=[("date", -1)]
        )
        return latest_history.get("comment", "No comments") if latest_history else "No comments"
    except Exception as e:
        print(f"Error getting latest comment: {str(e)}")
        return "Error"

def get_owner_name(user_id):
    """Helper function to get user name from ID"""
    if not user_id:
        return "N/A"
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user["email"] if user else "N/A"
    except Exception as e:
        print(f"Error getting owner name: {str(e)}")
        return "N/A"

# Update the login page layout
def render_login_page():
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H1([
                    html.I(className="fas fa-sign-in-alt me-2"),
                    "Login"
                ], className="text-center mb-4"),
                dbc.Card([
                    dbc.CardBody([
                        dbc.Input(
                            id="login-email",
                            type="email",
                            placeholder="Email",
                            className="mb-3",
                            style=CUSTOM_STYLES['input']
                        ),
                        dbc.Input(
                            id="login-password",
                            type="password",
                            placeholder="Password",
                            className="mb-3",
                            style=CUSTOM_STYLES['input']
                        ),
                        dbc.Button([
                            html.I(className="fas fa-sign-in-alt me-2"),
                            "Login"
                        ], id="login-button", color="primary", style=CUSTOM_STYLES['button']),
                        html.Div(id="login-message", className="mt-3"),
                        html.Hr(className="my-4"),
                        html.Div([
                            "Don't have an account? ",
                            dbc.Button([
                                html.I(className="fas fa-user-plus me-2"),
                                "Register"
                            ], href="/register", color="secondary", outline=True)
                        ], className="text-center")
                    ])
                ], style=CUSTOM_STYLES['card'])
            ], width=6, className="mx-auto")
        ])
    ])

def render_register_page():
    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H1([
                    html.I(className="fas fa-user-plus me-2"),
                    "Register New Account"
                ], className="text-center mb-4"),
                dbc.Card([
                    dbc.CardBody([
                        dbc.Input(
                            id="register-email",
                            type="email",
                            placeholder="Email",
                            className="mb-3",
                            style=CUSTOM_STYLES['input']
                        ),
                        dbc.Input(
                            id="register-password",
                            type="password",
                            placeholder="Password",
                            className="mb-3",
                            style=CUSTOM_STYLES['input']
                        ),
                        dbc.Input(
                            id="register-confirm-password",
                            type="password",
                            placeholder="Confirm Password",
                            className="mb-3",
                            style=CUSTOM_STYLES['input']
                        ),
                        dbc.Button([
                            html.I(className="fas fa-user-plus me-2"),
                            "Register"
                        ], id="register-button", color="primary", style=CUSTOM_STYLES['button']),
                        html.Div(id="register-message", className="mt-3"),
                        html.Hr(className="my-4"),
                        html.Div([
                            "Already have an account? ",
                            dbc.Button([
                                html.I(className="fas fa-sign-in-alt me-2"),
                                "Login"
                            ], href="/login", color="secondary", outline=True)
                        ], className="text-center")
                    ])
                ], style=CUSTOM_STYLES['card'])
            ], width=6, className="mx-auto")
        ])
    ])

# Create navigation bar
def create_navbar():
    nav_items = [
        dbc.NavItem(dbc.NavLink("Dashboard", href="/")),
        dbc.NavItem(dbc.NavLink("Reports", href="/reports")),
    ]
    
    if current_user.is_authenticated and current_user.role == 'admin':
        nav_items.append(dbc.NavItem(dbc.NavLink("Programs", href="/programs-page")))
    
    # Create the auth link based on authentication status
    auth_link = dbc.NavLink(
        current_user.email if current_user.is_authenticated else "Login",
        href="/logout" if current_user.is_authenticated else "/login",
        external_link=True  # This ensures the link is treated as an absolute path
    )
    
    return dbc.Navbar(
        dbc.Container([
            html.A(
                dbc.Row([
                    dbc.Col(html.I(className="fas fa-chart-line", style={"font-size": "1.5rem"})),
                    dbc.Col(dbc.NavbarBrand("KPI Dashboard", className="ms-2")),
                ], align="center", className="g-0"),
                href="/",
                style={"textDecoration": "none"},
            ),
            dbc.NavbarToggler(id="navbar-toggler", n_clicks=0),
            dbc.Collapse(
                dbc.Nav(nav_items, className="ms-auto", navbar=True),
                id="navbar-collapse",
                is_open=False,
                navbar=True,
            ),
            dbc.Nav([
                dbc.NavItem(auth_link)
            ], navbar=True)
        ], fluid=True),
        color="primary",
        dark=True,
        className="mb-4",
    )

def render_kpi_dashboard():
    if not current_user.is_authenticated:
        return html.Div([
            html.H1("Access Denied"),
            dbc.Alert("Please log in to create KPIs", color="danger"),
            dbc.Button("Login", href="/login", color="primary"),
        ])

    # Get available programs
    programs = list(mongo_db.programs.find())
    program_options = [{"label": p["name"], "value": p["name"]} for p in programs]

    return html.Div([
        html.H1([
            html.I(className="fas fa-chart-line me-2"),
            "KPI Dashboard"
        ], className="mb-4"),
        
        # Visualization Controls
        dbc.Card([
            dbc.CardHeader([
                html.H4([
                    html.I(className="fas fa-chart-bar me-2"),
                    "Visualization Settings"
                ], className="mb-0")
            ]),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.Label("Select Charts:", className="fw-bold mb-2"),
                        dbc.Checklist(
                            id="chart-selector",
                            options=[
                                {"label": "Performance Over Time", "value": "performance"},
                                {"label": "Target vs Actual", "value": "target"},
                                {"label": "Category Distribution", "value": "category"},
                                {"label": "KPI Gauges", "value": "gauges"},
                                {"label": "Monthly Trends", "value": "trends"},
                                {"label": "Achievement Rate", "value": "achievement"}
                            ],
                            value=["performance", "target", "category"],
                            inline=True,
                            switch=True
                        )
                    ], width=8),
                    dbc.Col([
                        html.Label("Time Range:", className="fw-bold mb-2"),
                        dbc.Select(
                            id="time-range",
                            options=[
                                {"label": "Last 7 Days", "value": "7d"},
                                {"label": "Last 30 Days", "value": "30d"},
                                {"label": "Last 90 Days", "value": "90d"},
                                {"label": "Year to Date", "value": "ytd"},
                                {"label": "All Time", "value": "all"}
                            ],
                            value="30d",
                            className="mb-2"
                        ),
                        dbc.Button([
                            html.I(className="fas fa-sync-alt me-2"),
                            "Refresh Charts"
                        ], id="refresh-charts", color="primary", size="sm", className="w-100")
                    ], width=4)
                ])
            ])
        ], className="mb-4"),
        
        # Charts Container
        dbc.Card([
            dbc.CardBody([
                dbc.Spinner(
                    html.Div(id="charts-container"),
                    color="primary",
                    type="border",
                    fullscreen=False
                )
            ])
        ], className="mb-4"),
        
        dbc.Row([
            # KPI Creation Form
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader([
                        html.H4([
                            html.I(className="fas fa-plus-circle me-2"),
                            "Create New KPI"
                        ], className="mb-0")
                    ]),
                    dbc.CardBody([
                        dbc.Input(
                            id="kpi-name",
                            placeholder="KPI Name",
                            type="text",
                            className="mb-3"
                        ),
                        dbc.Textarea(
                            id="kpi-description",
                            placeholder="Description",
                            className="mb-3"
                        ),
                        dbc.Select(
                            id="kpi-category",
                            options=program_options,
                            placeholder="Select Program",
                            className="mb-3"
                        ),
                        dbc.Select(
                            id="kpi-metric-type",
                            options=[
                                {"label": "Number", "value": "number"},
                                {"label": "Percentage", "value": "percentage"},
                                {"label": "Currency", "value": "currency"},
                                {"label": "Time", "value": "time"}
                            ],
                            placeholder="Select Metric Type",
                            className="mb-3"
                        ),
                        dbc.InputGroup([
                            dbc.InputGroupText("Current Value"),
                            dbc.Input(
                                id="kpi-current-value",
                                type="number",
                                placeholder="Enter current value"
                            )
                        ], className="mb-3"),
                        dbc.InputGroup([
                            dbc.InputGroupText("Target Value"),
                            dbc.Input(
                                id="kpi-target",
                                type="number",
                                placeholder="Enter target value"
                            )
                        ], className="mb-3"),
                        dbc.Input(
                            id="kpi-date",
                            type="date",
                            value=datetime.now().strftime("%Y-%m-%d"),
                            className="mb-3"
                        ),
                        dbc.Button([
                            html.I(className="fas fa-plus-circle me-2"),
                            "Create KPI"
                        ], id="create-kpi-button", color="primary", className="w-100"),
                        html.Div(id="kpi-message", className="mt-3")
                    ])
                ])
            ], width=4),
            
            # KPI List
            dbc.Col([
                html.Div(id="kpi-list")
            ], width=8)
        ])
    ])

# Add callback to handle edit program modal
@app.callback(
    [Output("edit-program-modal", "is_open"),
     Output("edit-program-name", "value"),
     Output("edit-program-description", "value"),
     Output("edit-program-id", "value")],
    [Input({"type": "edit-program", "index": ALL}, "n_clicks"),
     Input("edit-program-close", "n_clicks"),
     Input("save-program-edit", "n_clicks")],
    [State("edit-program-modal", "is_open")]
)
def toggle_edit_program_modal(edit_clicks, close_click, save_click, is_open):
    ctx = dash.callback_context
    if not ctx.triggered:
        return False, "", "", ""
    
    trigger_id = ctx.triggered[0]["prop_id"]
    
    if trigger_id == "edit-program-close.n_clicks" or trigger_id == "save-program-edit.n_clicks":
        return False, "", "", ""
    
    if not any(edit_clicks):
        raise PreventUpdate
    
    # Find which edit button was clicked
    for i, clicks in enumerate(edit_clicks):
        if clicks:
            # Get the program ID from the button's index
            program_id = ctx.inputs_list[0][i]["id"]["index"]
            # Fetch program data from MongoDB
            program = mongo_db.programs.find_one({"_id": ObjectId(program_id)})
            if program:
                return True, program.get("name", ""), program.get("description", ""), program_id
    
    raise PreventUpdate

if __name__ == '__main__':
    app.run(
        debug=True,
        host='localhost',
        port=8050
    ) 