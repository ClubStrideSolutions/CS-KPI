from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc
from datetime import datetime
import plotly.graph_objects as go
from app import app, mongo_db
from flask_login import current_user
from report_generator import generate_kpi_report
import os

def dashboard_layout():
    return html.Div([
        dbc.Container([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Create New KPI"),
                        dbc.CardBody([
                            dbc.Input(id="kpi-name", placeholder="KPI Name", className="mb-3"),
                            dbc.Input(id="kpi-target", type="number", placeholder="Target Value", className="mb-3"),
                            dbc.Input(id="kpi-unit", placeholder="Unit (e.g., %, $, items)", className="mb-3"),
                            dbc.Select(
                                id="kpi-frequency",
                                options=[
                                    {"label": "Daily", "value": "daily"},
                                    {"label": "Weekly", "value": "weekly"},
                                    {"label": "Monthly", "value": "monthly"},
                                    {"label": "Quarterly", "value": "quarterly"},
                                    {"label": "Yearly", "value": "yearly"}
                                ],
                                className="mb-3"
                            ),
                            dbc.Button("Create KPI", id="create-kpi-button", color="primary")
                        ])
                    ], className="mb-4")
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.Div([
                                html.H5("Your KPIs", className="d-inline"),
                                dbc.Button("Export to Excel", id="export-button", color="success", className="float-end")
                            ])
                        ]),
                        dbc.CardBody([
                            html.Div(id="kpi-list"),
                            html.Div(id="export-message", className="mt-3")
                        ])
                    ])
                ], width=6)
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("KPI Progress"),
                        dbc.CardBody([
                            dcc.Graph(id="kpi-progress-graph")
                        ])
                    ])
                ], width=12)
            ], className="mt-4")
        ])
    ])

# Callbacks for KPI management
@app.callback(
    Output("kpi-list", "children"),
    [Input("create-kpi-button", "n_clicks")],
    [State("kpi-name", "value"),
     State("kpi-target", "value"),
     State("kpi-unit", "value"),
     State("kpi-frequency", "value")]
)
def update_kpi_list(n_clicks, name, target, unit, frequency):
    if n_clicks is not None and all([name, target, unit, frequency]):
        # Create new KPI
        kpi = {
            "user_id": current_user.id,
            "name": name,
            "target": target,
            "unit": unit,
            "frequency": frequency,
            "created_at": datetime.now()
        }
        mongo_db.kpis.insert_one(kpi)
    
    # Get all KPIs for current user
    kpis = list(mongo_db.kpis.find({"user_id": current_user.id}))
    
    if not kpis:
        return html.P("No KPIs created yet.")
    
    return html.Div([
        dbc.ListGroup([
            dbc.ListGroupItem([
                html.H5(kpi["name"]),
                html.P(f"Target: {kpi['target']} {kpi['unit']}"),
                html.P(f"Frequency: {kpi['frequency']}"),
                dbc.Button("Add Progress", id=f"add-progress-{kpi['_id']}", color="success", size="sm", className="me-2"),
                dbc.Button("Delete", id=f"delete-kpi-{kpi['_id']}", color="danger", size="sm")
            ]) for kpi in kpis
        ])
    ])

@app.callback(
    Output("kpi-progress-graph", "figure"),
    [Input("kpi-list", "children")]
)
def update_progress_graph(_):
    kpis = list(mongo_db.kpis.find({"user_id": current_user.id}))
    if not kpis:
        return go.Figure()
    
    fig = go.Figure()
    
    for kpi in kpis:
        progress = list(mongo_db.kpi_history.find({"kpi_id": str(kpi["_id"])}))
        if progress:
            dates = [p["date"] for p in progress]
            values = [p["value"] for p in progress]
            fig.add_trace(go.Scatter(
                x=dates,
                y=values,
                name=kpi["name"],
                mode="lines+markers"
            ))
    
    fig.update_layout(
        title="KPI Progress Over Time",
        xaxis_title="Date",
        yaxis_title="Value",
        showlegend=True
    )
    
    return fig

@app.callback(
    Output("kpi-list", "children", allow_duplicate=True),
    [Input({"type": "delete-kpi", "index": dcc.ALL}, "n_clicks")],
    prevent_initial_call=True
)
def delete_kpi(n_clicks):
    if not n_clicks or all(click is None for click in n_clicks):
        return dash.no_update
    
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update
    
    button_id = ctx.triggered[0]["prop_id"].split(".")[0]
    kpi_id = button_id.split("-")[-1]
    
    # Delete KPI and its history
    mongo_db.kpis.delete_one({"_id": kpi_id})
    mongo_db.kpi_history.delete_many({"kpi_id": kpi_id})
    
    # Return updated KPI list
    kpis = list(mongo_db.kpis.find({"user_id": current_user.id}))
    if not kpis:
        return html.P("No KPIs created yet.")
    
    return html.Div([
        dbc.ListGroup([
            dbc.ListGroupItem([
                html.H5(kpi["name"]),
                html.P(f"Target: {kpi['target']} {kpi['unit']}"),
                html.P(f"Frequency: {kpi['frequency']}"),
                dbc.Button("Add Progress", id=f"add-progress-{kpi['_id']}", color="success", size="sm", className="me-2"),
                dbc.Button("Delete", id=f"delete-kpi-{kpi['_id']}", color="danger", size="sm")
            ]) for kpi in kpis
        ])
    ])

@app.callback(
    Output("export-message", "children"),
    [Input("export-button", "n_clicks")]
)
def export_to_excel(n_clicks):
    if n_clicks is None:
        return ""
    
    try:
        filepath = generate_kpi_report()
        filename = os.path.basename(filepath)
        return dbc.Alert(
            [
                html.P("Report generated successfully!"),
                html.A(
                    "Download Excel Report",
                    href=f"/download/{filename}",
                    className="btn btn-success mt-2"
                )
            ],
            color="success"
        )
    except Exception as e:
        return dbc.Alert(f"Error generating report: {str(e)}", color="danger")

# Add this to your app.py to handle file downloads
@app.server.route("/download/<filename>")
def download_file(filename):
    return send_from_directory("reports", filename, as_attachment=True) 