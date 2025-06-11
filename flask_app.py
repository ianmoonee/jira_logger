from flask import Flask, render_template, request, redirect, url_for, flash, session
import requests
import datetime
import re
import pandas as pd
from jiraLogger import get_excel_entry
import pathlib
from markupsafe import escape

app = Flask(__name__)
app.secret_key = 'asdasd'  # Replace with a random, secure value

JIRA_DOMAIN = 'https://jira.critical.pt'

def get_pat():
    """Retrieve the JIRA Personal Access Token from session only."""
    return session.get('JIRA_PAT')

def get_headers():
    """Return headers for JIRA API requests, including authorization if available."""
    pat = get_pat()
    return {
        'Authorization': f'Bearer {pat}' if pat else '',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

@app.before_request
def require_pat():
    """Require a JIRA PAT for all endpoints except set_pat and static files."""
    if request.endpoint not in ('set_pat', 'static'):
        pat = get_pat()
        if not pat:
            return redirect(url_for('set_pat'))

@app.route('/set_pat', methods=['GET', 'POST'])
def set_pat():
    """Allow the user to set their JIRA PAT via a form."""
    if request.method == 'POST':
        pat = request.form.get('pat')
        if pat:
            session['JIRA_PAT'] = pat
            flash('JIRA PAT set successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Please enter a valid JIRA PAT.', 'danger')
    return render_template('set_pat.html')

def get_assigned_tasks():
    """Fetch all tasks assigned to the current user from JIRA."""
    assigned_url = f'{JIRA_DOMAIN}/rest/api/2/search'
    jql = 'assignee = currentUser() ORDER BY updated DESC'
    params = {'jql': jql, 'maxResults': 100}
    response = requests.get(assigned_url, headers=get_headers(), params=params)
    if response.status_code != 200:
        return [], f"Failed to fetch tasks: {response.status_code} {response.text}"
    issues = response.json().get('issues', [])
    return issues, None

def log_work(issue_key, time_spent, started):
    """Log work for a given JIRA issue key."""
    worklog_url = f'{JIRA_DOMAIN}/rest/api/2/issue/{issue_key}/worklog'
    worklog_payload = {
        "started": started,
        "timeSpent": time_spent
    }
    response = requests.post(worklog_url, headers=get_headers(), json=worklog_payload)
    if response.status_code == 201:
        return True, f"Successfully logged {time_spent} on {issue_key}"
    else:
        return False, f"Failed to log work: {response.status_code} {response.text}"

@app.route('/', methods=['GET', 'POST'])
def index():
    """Main page: show tasks, allow filtering and sorting."""
    sort_by = request.args.get('sort_by', 'summary')
    sort_order = request.args.get('sort_order', 'desc')
    filter_keyword = request.form.get('filter', '').lower() if request.method == 'POST' else request.args.get('filter', '').lower()

    # Always fetch tasks when loading the page
    tasks, error = get_assigned_tasks()
    if error:
        flash(error, 'danger')
        tasks = []
    if filter_keyword:
        tasks = [t for t in tasks if filter_keyword in t['fields']['summary'].lower()]

    # Sorting
    if tasks:
        reverse = (sort_order == 'desc')
        if sort_by == 'summary':
            tasks = sorted(tasks, key=lambda t: t['fields']['summary'].lower(), reverse=reverse)
        else:
            tasks = sorted(tasks, key=lambda t: t['key'], reverse=reverse)
    return render_template('index.html', tasks=tasks, filter_keyword=filter_keyword, sort_by=sort_by, sort_order=sort_order)

@app.route('/log_time/<issue_key>', methods=['GET', 'POST'])
def log_time(issue_key):
    """Log time for a single JIRA issue."""
    issue_key = sanitize_text(issue_key, max_length=20)
    time_spent = ''
    date_input = ''
    dry_run = False
    # Fetch summary for the issue_key
    all_tasks, _ = get_assigned_tasks()
    summary = next((t['fields']['summary'] for t in all_tasks if t['key'] == issue_key), '')
    if request.method == 'POST':
        time_spent = request.form.get('time_spent', '')
        date_input = request.form.get('date_input', '')
        if 'dry_run' in request.form:
            # Just show dry run summary
            dry_run = True
            return render_template('log_time.html', issue_key=issue_key, summary=summary, time_spent=time_spent, date_input=date_input, dry_run=True)
        elif 'confirm' in request.form:
            # Actually log time
            try:
                if date_input:
                    started = datetime.datetime.strptime(date_input, "%H:%M %d-%m-%Y").strftime('%Y-%m-%dT%H:%M:%S.000+0000')
                else:
                    started = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000+0000')
            except ValueError:
                flash("Invalid date format. Use HH:MM DD-MM-YYYY.", 'danger')
                return render_template('log_time.html', issue_key=issue_key, summary=summary, time_spent=time_spent, date_input=date_input, dry_run=True)
            success, msg = log_work(issue_key, time_spent, started)
            flash(msg, 'success' if success else 'danger')
            # Do NOT clear or update session['tasks'] here, just redirect
            return redirect(url_for('index'))
    return render_template('log_time.html', issue_key=issue_key, summary=summary, time_spent=time_spent, date_input=date_input, dry_run=dry_run)

@app.route('/log_time_multiple', methods=['POST', 'GET'])
def log_time_multiple():
    """Log time for multiple selected JIRA issues at once."""
    if request.method == 'POST':
        selected_tasks = [sanitize_text(k, max_length=20) for k in request.form.getlist('selected_tasks')]
        if not selected_tasks:
            flash('No tasks selected.', 'danger')
            return redirect(url_for('index'))
        all_tasks, _ = get_assigned_tasks()
        key_to_summary = {t['key']: t['fields']['summary'] for t in all_tasks}
        selected_task_info = [(key, key_to_summary.get(key, '')) for key in selected_tasks]
        if 'confirm' in request.form:
            # Actually log work after dry run
            time_spent = sanitize_text(request.form['time_spent'], max_length=20)
            date_input = sanitize_text(request.form['date_input'], max_length=30)
            try:
                if date_input:
                    started = datetime.datetime.strptime(date_input, "%H:%M %d-%m-%Y").strftime('%Y-%m-%dT%H:%M:%S.000+0000')
                else:
                    started = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000+0000')
            except ValueError:
                flash("Invalid date format. Use HH:MM DD-MM-YYYY.", 'danger')
                return render_template('log_time_multiple.html', selected_tasks=selected_tasks, selected_task_info=selected_task_info, time_spent=time_spent, date_input=date_input, dry_run=True)
            for issue_key in selected_tasks:
                success, msg = log_work(issue_key, time_spent, started)
                flash(msg, 'success' if success else 'danger')
            return redirect(url_for('index'))
        elif 'time_spent' in request.form:
            # Always show dry run before logging
            time_spent = sanitize_text(request.form['time_spent'], max_length=20)
            date_input = sanitize_text(request.form['date_input'], max_length=30)
            return render_template('log_time_multiple.html', selected_tasks=selected_tasks, selected_task_info=selected_task_info, time_spent=time_spent, date_input=date_input, dry_run=True)
        else:
            now = datetime.datetime.now().strftime('%H:%M %d-%m-%Y')
            return render_template('log_time_multiple.html', selected_tasks=selected_tasks, selected_task_info=selected_task_info, date_input=now)
    else:
        return redirect(url_for('index'))

@app.route('/log_time_multiple_individual', methods=['GET', 'POST'])
def log_time_multiple_individual():
    """Log time for multiple JIRA issues, each with individual time/date."""
    def is_valid_time_spent(val):
        """Check if the time spent string is valid (e.g. 1h, 10m, 1h10m)."""
        return bool(re.fullmatch(r'([0-9]+h)?([0-9]+m)?', val.strip())) and val.strip() != ''

    def parse_time_spent(val):
        """Parse a time spent string into hours and minutes as integers."""
        match = re.fullmatch(r'(?:(\d+)h)?(?:(\d+)m)?', val.strip())
        if not match:
            return 0, 0
        hours = int(match.group(1)) if match.group(1) else 0
        minutes = int(match.group(2)) if match.group(2) else 0
        return hours, minutes

    if request.method == 'POST':
        selected_tasks = [sanitize_text(k, max_length=20) for k in request.form.getlist('selected_tasks')]
        if not selected_tasks:
            flash('No tasks selected.', 'danger')
            return redirect(url_for('index'))
        all_tasks, _ = get_assigned_tasks()
        key_to_summary = {t['key']: t['fields']['summary'] for t in all_tasks}
        selected_task_info = [(key, key_to_summary.get(key, '')) for key in selected_tasks]
        if 'dry_run' in request.form:
            # Show dry run summary with status for each
            per_task_data = []
            for key in selected_tasks:
                time_spent = sanitize_text(request.form.get(f'time_spent_{key}'), max_length=20)
                date_input = sanitize_text(request.form.get(f'date_input_{key}'), max_length=30)
                status = 'ok'
                # Validate input
                if not time_spent or not is_valid_time_spent(time_spent):
                    status = 'Invalid time (use e.g. 1h10m, 10m, 2h)'
                try:
                    if date_input:
                        datetime.datetime.strptime(date_input, "%H:%M %d-%m-%Y")
                except Exception:
                    status = 'Invalid date'
                per_task_data.append({'key': key, 'summary': key_to_summary.get(key, ''), 'time_spent': time_spent, 'date_input': date_input, 'status': status})
            return render_template('log_time_multiple_individual.html', selected_tasks=selected_tasks, selected_task_info=selected_task_info, per_task_data=per_task_data, dry_run=True)
        elif 'confirm' in request.form:
            # Actually log work for all tasks
            for key in selected_tasks:
                time_spent = sanitize_text(request.form.get(f'time_spent_{key}'), max_length=20)
                date_input = sanitize_text(request.form.get(f'date_input_{key}'), max_length=30)
                if not time_spent or not is_valid_time_spent(time_spent):
                    flash(f"Invalid time for {key}. Use e.g. 1h10m, 10m, 2h", 'danger')
                    return redirect(request.url)
                # If only hours, add 0m for display/logging clarity
                hours, minutes = parse_time_spent(time_spent)
                formatted_time_spent = ''
                if hours:
                    formatted_time_spent += f'{hours}h'
                if minutes or not hours:
                    formatted_time_spent += f'{minutes}m'
                try:
                    if date_input:
                        started = datetime.datetime.strptime(date_input, "%H:%M %d-%m-%Y").strftime('%Y-%m-%dT%H:%M:%S.000+0000')
                    else:
                        started = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000+0000')
                except ValueError:
                    flash(f"Invalid date format for {key}. Use HH:MM DD-MM-YYYY.", 'danger')
                    return redirect(request.url)
                success, msg = log_work(key, formatted_time_spent, started)
                flash(msg, 'success' if success else 'danger')
            return redirect(url_for('index'))
        else:
            return render_template('log_time_multiple_individual.html', selected_tasks=selected_tasks, selected_task_info=selected_task_info)
    else:
        # GET: parse selected_tasks from query string
        selected_tasks = request.args.getlist('selected_tasks')
        default_date = request.args.get('default_date')
        if not selected_tasks:
            flash('No tasks selected.', 'danger')
            return redirect(url_for('index'))
        all_tasks, _ = get_assigned_tasks()
        key_to_summary = {t['key']: t['fields']['summary'] for t in all_tasks}
        selected_task_info = [(key, key_to_summary.get(key, '')) for key in selected_tasks]
        # If default_date is present, format as 09:00 DD-MM-YYYY if only a date, else use as is
        default_date_input = None
        if default_date:
            for fmt in ('%d-%m-%Y', '%d/%m/%Y'):
                try:
                    dt = datetime.datetime.strptime(default_date, fmt)
                    default_date_input = dt.strftime('09:00 %d-%m-%Y')
                    break
                except Exception:
                    continue
            if not default_date_input:
                default_date_input = default_date
        return render_template('log_time_multiple_individual.html', selected_tasks=selected_tasks, selected_task_info=selected_task_info, default_date_input=default_date_input)

@app.route('/excel_log', methods=['GET', 'POST'])
def excel_log():
    """Show a form to fetch a cell from an Excel file, with editable file path."""
    value1 = ''
    value2 = ''
    file_path = '/mnt/c/Users/peserrano/OneDrive - CRITICAL SOFTWARE, S.A/BSP_G2/BSP-G2_Daily_Tracker.xlsx'
    result = None
    if request.method == 'POST':
        value1 = sanitize_text(request.form.get('value1', ''))  # Name
        value2 = sanitize_text(request.form.get('value2', ''))  # Date
        file_path = sanitize_filename(request.form.get('file_path', file_path))
        if value1 and value2 and file_path:
            cell = get_excel_entry(value2, value1, file_path=file_path)
            result = cell
    return render_template('excel_log.html', value1=value1, value2=value2, file_path=file_path, result=result)

@app.route('/read_tasks', methods=['GET'])
def read_tasks():
    """Show the form to paste or enter a list of tasks for matching."""
    return render_template('read_tasks.html')

@app.route('/process_read_tasks', methods=['POST'])
def process_read_tasks():
    """Process pasted task lines, match to JIRA summaries, and redirect to log page."""
    import re
    input_text = request.form.get('tasklist', '')
    if not input_text:
        flash('No tasks provided.', 'danger')
        return redirect(url_for('read_tasks'))

    lines = [line.strip('-').strip() for line in input_text.splitlines() if line.strip()]
    all_tasks, _ = get_assigned_tasks()
    summary_to_key = {t['fields']['summary']: t['key'] for t in all_tasks}
    matched_keys = set()

    for line in lines:
        lowered = line.lower()

        # Extract verb
        verb_match = re.search(r'\b(author|review|rework)\b', lowered)
        verb = verb_match.group(1).capitalize() if verb_match else None

        # Normalize verb to task summary keyword
        if verb in ['Author', 'Rework']:
            summary_verb = 'Authoring'
        elif verb == 'Review':
            summary_verb = 'Review'
        else:
            continue  # skip if verb not found

        # Extract type and base
        match = re.search(
            r'\b(?:author|review|rework)[^a-zA-Z0-9]*\d*\s*(tcs?/tps?|tps?/tcs?|tcs?|tps?)?\s*([a-zA-Z0-9_]+)\s*$',
            lowered,
            re.IGNORECASE
        )
        if not match:
            continue  # skip invalid line

        type_indicator = match.group(1)
        base = match.group(2)

        # Determine types to match
        if type_indicator and 'tc' in type_indicator.lower() and 'tp' in type_indicator.lower():
            types_to_check = ['TC', 'TP']
        elif type_indicator:
            if 'tc' in type_indicator.lower():
                types_to_check = ['TC']
            elif 'tp' in type_indicator.lower():
                types_to_check = ['TP']
            else:
                types_to_check = [None]
        else:
            types_to_check = [None]

        # Match task summaries
        for summary, key in summary_to_key.items():
            normalized_summary = re.sub(r'\s+', ' ', summary)
            if summary_verb not in normalized_summary:
                continue
            if base.lower() not in normalized_summary.lower():
                continue
            if types_to_check == [None]:
                matched_keys.add(key)
            else:
                for typ in types_to_check:
                    if re.search(r'\b' + re.escape(typ) + r'\b', normalized_summary):
                        matched_keys.add(key)

    if not matched_keys:
        flash('No valid tasks found from input.', 'danger')
        return redirect(url_for('read_tasks'))

    return redirect(url_for('log_time_multiple_individual', **{'selected_tasks': list(matched_keys)}))


@app.route('/log_from_excel_cell', methods=['POST'])
def log_from_excel_cell():
    """Process tasks from an Excel cell, match to JIRA summaries, and redirect to log page."""
    value1 = sanitize_text(request.form.get('value1', ''))
    value2 = sanitize_text(request.form.get('value2', ''))
    file_path = sanitize_filename(request.form.get('file_path', 'BSP-G2_Daily_Tracker.xlsx'))
    if not value1 or not value2 or not file_path:
        flash('Name, date, and file path are required.', 'danger')
        return redirect(url_for('excel_log'))
    cell = get_excel_entry(value2, value1, file_path=file_path)
    if not cell:
        flash('No cell data found.', 'danger')
        return redirect(url_for('excel_log'))
    # Parse tasks from cell (split by lines, remove empty)
    lines = [line.strip('-').strip() for line in str(cell).splitlines() if line.strip()]
    all_tasks, _ = get_assigned_tasks()
    summary_to_key = {t['fields']['summary']: t['key'] for t in all_tasks}
    matched_keys = set()
    for line in lines:
        lowered = line.lower()
        # Extract verb (author, review, rework)
        verb_match = re.search(r'\b(author|review|rework)\b', lowered)
        verb = verb_match.group(1).capitalize() if verb_match else None
        verb_map = {'Author': 'Authoring', 'Review': 'Review', 'Rework': 'Authoring'}
        summary_verb = verb_map.get(verb, None)
        if summary_verb:
            match = re.search(r'(?:' + verb.lower() + r')[^a-zA-Z0-9]*\d*\s*(?:tcs?/tps?|tps?/tcs?|tcs?|tps?)?\s*([a-zA-Z0-9_]+)\s*$', line, re.IGNORECASE)
            if match:
                base = match.group(1)
                has_tc = re.search(r'\bTCs?\b', line, re.IGNORECASE)
                has_tp = re.search(r'\bTPs?\b', line, re.IGNORECASE)
                has_both = re.search(r'(TCs?/TPs?|TPs?/TCs?)', line, re.IGNORECASE)
                types_to_check = []
                if has_both or (has_tc and has_tp):
                    types_to_check = ['TC', 'TP']
                elif has_tc:
                    types_to_check = ['TC']
                elif has_tp:
                    types_to_check = ['TP']
                else:
                    types_to_check = [None]
                for typ in types_to_check:
                    for summary, key in summary_to_key.items():
                        if summary_verb in summary and base.lower() in summary.lower():
                            if typ:
                                if re.search(r'\b' + typ + r'\b', summary):
                                    matched_keys.add(key)
                            else:
                                matched_keys.add(key)
        else:
            for summary, key in summary_to_key.items():
                if line.lower() in summary.lower():
                    matched_keys.add(key)
    if not matched_keys:
        flash('No valid tasks found in Excel cell.', 'danger')
        return redirect(url_for('excel_log'))
    # Pass the searched date as default_date to the log_time_multiple_individual page
    return redirect(url_for('log_time_multiple_individual', **{'selected_tasks': list(matched_keys), 'default_date': value2}))

@app.route('/clear_pat')
def clear_pat():
    session.pop('JIRA_PAT', None)
    flash('PAT cleared from session.', 'success')
    return redirect(url_for('set_pat'))

def sanitize_filename(filename):
    """Allow any path, but block path traversal and suspicious characters."""
    filename = str(filename)
    # Disallow path traversal
    if '..' in filename or filename.strip() == '':
        return 'BSP-G2_Daily_Tracker.xlsx'
    # Optionally, allow only certain file extensions (e.g., .xlsx)
    if not filename.lower().endswith('.xlsx'):
        return 'BSP-G2_Daily_Tracker.xlsx'
    return filename

def sanitize_text(text, max_length=100):
    """Escape and trim user text input."""
    return escape(str(text)[:max_length])

if __name__ == '__main__':
    app.run(debug=True)
