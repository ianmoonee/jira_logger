import requests
import datetime
import os
import time
import pandas as pd

# === CONFIG ===
JIRA_DOMAIN = 'https://jira.critical.pt'
PAT = os.getenv('JIRA_PAT')  # Ensure you export JIRA_PAT in your bashrc

HEADERS = {
    'Authorization': f'Bearer {PAT}',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
}

# === FUNCTIONS ===
def get_assigned_tasks():
    assigned_url = f'{JIRA_DOMAIN}/rest/api/2/search'
    jql = 'assignee = currentUser() ORDER BY updated DESC'
    params = {'jql': jql, 'maxResults': 100}

    response = requests.get(assigned_url, headers=HEADERS, params=params)
    if response.status_code != 200:
        return []

    issues = response.json().get('issues', [])
    return issues

def log_work(issue_key, time_spent, started):
    worklog_url = f'{JIRA_DOMAIN}/rest/api/2/issue/{issue_key}/worklog'
    worklog_payload = {
        "started": started,
        "timeSpent": time_spent
    }

    response = requests.post(worklog_url, headers=HEADERS, json=worklog_payload)
    return response.status_code == 201

def get_excel_entry(date_str, name, file_path='BSP-G2_Daily_Tracker.xlsx', sheet_name='Daily'):
    """
    Returns the cell value for the given name (column) on the given date (DD/MM/YYYY) from the Excel file.
    """
    try:
        date_obj = pd.to_datetime(date_str, format='%d/%m/%Y', dayfirst=True)
    except Exception:
        return "Invalid date format. Use DD/MM/YYYY."
    df = pd.read_excel(file_path, sheet_name=sheet_name)
    df['Days'] = pd.to_datetime(df['Days'], errors='coerce')
    if name not in df.columns:
        return f"No column named '{name}' in sheet '{sheet_name}'."
    row = df[df['Days'].dt.date == date_obj.date()]
    if row.empty:
        return f"No entry found for date {date_str}."
    return row[name].values[0]