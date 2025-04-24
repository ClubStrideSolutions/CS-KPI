import pandas as pd
from datetime import datetime
import os
from app import mongo_db
from flask_login import current_user

def generate_kpi_report():
    # Get all KPIs for the current user
    kpis = list(mongo_db.kpis.find({"user_id": current_user.id}))
    
    # Create a DataFrame for KPIs
    kpi_data = []
    for kpi in kpis:
        # Get the latest progress for each KPI
        latest_progress = mongo_db.kpi_history.find_one(
            {"kpi_id": str(kpi["_id"])},
            sort=[("date", -1)]
        )
        
        kpi_data.append({
            "KPI Name": kpi["name"],
            "Target Value": kpi["target"],
            "Unit": kpi["unit"],
            "Frequency": kpi["frequency"],
            "Current Value": latest_progress["value"] if latest_progress else None,
            "Last Updated": latest_progress["date"].strftime("%Y-%m-%d") if latest_progress else "N/A",
            "Status": "On Track" if latest_progress and latest_progress["value"] >= kpi["target"] else "Needs Attention"
        })
    
    # Create DataFrame
    df = pd.DataFrame(kpi_data)
    
    # Create Excel writer
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"kpi_report_{current_user.email}_{timestamp}.xlsx"
    filepath = os.path.join("reports", filename)
    
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)
    
    # Create Excel writer with XlsxWriter engine
    writer = pd.ExcelWriter(filepath, engine='xlsxwriter')
    
    # Write DataFrame to Excel
    df.to_excel(writer, sheet_name='KPI Dashboard', index=False)
    
    # Get workbook and worksheet objects
    workbook = writer.book
    worksheet = writer.sheets['KPI Dashboard']
    
    # Define formats
    header_format = workbook.add_format({
        'bold': True,
        'text_wrap': True,
        'valign': 'top',
        'fg_color': '#D7E4BC',
        'border': 1
    })
    
    cell_format = workbook.add_format({
        'border': 1,
        'text_wrap': True
    })
    
    # Format the worksheet
    for col_num, value in enumerate(df.columns.values):
        worksheet.write(0, col_num, value, header_format)
        worksheet.set_column(col_num, col_num, 15)  # Set column width
    
    # Apply cell format to all data cells
    for row in range(1, len(df) + 1):
        for col in range(len(df.columns)):
            worksheet.write(row, col, df.iloc[row-1, col], cell_format)
    
    # Add conditional formatting for Status column
    status_col = df.columns.get_loc("Status")
    worksheet.conditional_format(1, status_col, len(df), status_col, {
        'type': 'text',
        'criteria': 'containing',
        'value': 'On Track',
        'format': workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100'})
    })
    
    worksheet.conditional_format(1, status_col, len(df), status_col, {
        'type': 'text',
        'criteria': 'containing',
        'value': 'Needs Attention',
        'format': workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
    })
    
    # Add a summary section
    summary_row = len(df) + 3
    worksheet.write(summary_row, 0, "Summary", header_format)
    worksheet.write(summary_row + 1, 0, "Total KPIs", cell_format)
    worksheet.write(summary_row + 1, 1, len(df), cell_format)
    
    on_track = len(df[df['Status'] == 'On Track'])
    worksheet.write(summary_row + 2, 0, "KPIs On Track", cell_format)
    worksheet.write(summary_row + 2, 1, on_track, cell_format)
    
    needs_attention = len(df[df['Status'] == 'Needs Attention'])
    worksheet.write(summary_row + 3, 0, "KPIs Needing Attention", cell_format)
    worksheet.write(summary_row + 3, 1, needs_attention, cell_format)
    
    # Save the Excel file
    writer.close()
    
    return filepath 