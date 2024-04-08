import psutil
import re
import time
import json
import requests
from datetime import datetime
now = datetime.now()


def get_application_uptime_by_user():
    """
    This function iterates through running processes and retrieves the uptime of applications,
    grouping them by user and keeping track of the highest uptime for processes with the same name.
    """

    # Dictionary to store application information grouped by user
    app_info = {}
    for proc in psutil.process_iter():
        try:
            username = proc.username()
            process_name = proc.name()
            # Filter out non-application processes (e.g., system processes)
            if not process_name.endswith('.exe'):
                continue
            # Filter out processes located in system directories
            if any(dir_name in proc.exe().lower() for dir_name in ["system32", "program files (x86)", "windows"]):
                continue
            # Filter out specified processes
            if process_name.lower() in ["tabtip.exe", "displaylinktrayapp.exe", "pangpa.exe", "state-svc.exe",
                                        "nxtray.exe", "nxtusm.exe", "mottynew.exe", "fsnotifier.exe",
                                        "filecoauth.exe", "code.exe", "xwin_mobax.exe", "ai.exe"]:
                continue
            # Filter out processes that don't belong to the specified user
            if username != r"<YOUR USERNAME>":
                continue
            # Create entry for user if it doesn't exist
            if username not in app_info:
                app_info[username] = {}
            # Get process creation time in seconds since epoch
            create_time = proc.create_time()
            # Get current time in seconds since epoch
            now = time.time()
            # Calculate uptime in seconds
            uptime = now - create_time

            # Extract numerical uptime from existing value (if any)
            existing_uptime = app_info[username].get(process_name, {'uptime': None, 'memory_usage': 0})
            numerical_uptime = extract_numerical_uptime(existing_uptime['uptime'])

            # Update application info only if it's the highest uptime for the name
            if process_name not in app_info[username] or uptime > numerical_uptime:
                # Convert uptime to human-readable format (hours, minutes, seconds)
                hours, remainder = divmod(uptime, 3600)
                minutes, seconds = divmod(remainder, 60)
                # Limit seconds to two units
                seconds = round(seconds, 2)
                uptime_str = f"{hours} hours, {minutes} minutes, {seconds} seconds"
                # Get memory usage
                memory_usage = proc.memory_info().rss
                # Accumulate memory usage as integer
                memory_usage_total = existing_uptime['memory_usage'] + memory_usage

                app_info[username][process_name] = {'uptime': uptime_str, 'memory_usage': memory_usage_total}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Flatten the app_info dictionary to extract all applications
    all_apps = [(user, app_name, info) for user, processes in app_info.items() for app_name, info in processes.items()]
    # Sort applications based on uptime (highest uptime first)
    sorted_apps = sorted(all_apps, key=lambda x: extract_numerical_uptime(x[2]['uptime']), reverse=True)

    # Create a list to hold the top 10 applications
    top_apps = []
    for i, (user, app_name, info) in enumerate(sorted_apps[:10], start=1):
        # Calculate memory utilization percentage
        total_memory = psutil.virtual_memory().total
        memory_percent = (info['memory_usage'] / total_memory) * 100
        # Calculate memEnergy
        mem_energy = ((memory_percent / 100) * (32)) * 0.000392
        # Calculate the additional value
        additional_value = mem_energy * 1.1

        top_apps.append({
            'user': user,
            'application': app_name,
            'uptime': info['uptime'],
            'memory_usage': convert_bytes(info['memory_usage']),
            'memory_utilization_percentage': round(memory_percent, 2),
            'memEnergy': round(mem_energy, 6),
            'CarbonEmission': round(additional_value, 6)
        })

    # Output the top 10 applications as JSON
    output_json = json.dumps({'top_applications': top_apps}, indent=4)
    return output_json


def extract_numerical_uptime(uptime_str):
    """
    This function attempts to extract numerical uptime (seconds) from a human-readable string.
    """
    if not isinstance(uptime_str, str):
        return 0
    match = re.search(r"(\d+\.?\d*) (seconds|minutes|hours)", uptime_str, re.IGNORECASE)
    if match:
        value, unit = match.groups()
        # Convert to seconds based on unit
        if unit == "hours":
            return float(value) * 3600
        elif unit == "minutes":
            return float(value) * 60
        else:
            return float(value)
    else:
        return 0  # Handle cases where uptime_str is not in expected format


def convert_bytes(num):
    """
    Convert bytes to human-readable format.
    """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

    return "%3.1f %s" % (num, 'TB')


data = (get_application_uptime_by_user())

def createReport(data_string):
    try:
        data = json.loads(data_string)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return

    if "top_applications" not in data:
        print("Error: 'top_applications' key not found in JSON data")
        return

    top_applications = data["top_applications"]

    report_data = ""
    for app_data in top_applications:
        name = app_data["application"]
        uptime = app_data["uptime"]
        carbon_emission = app_data["CarbonEmission"]
        total_carbon = extract_numerical_uptime(uptime) * carbon_emission  # Calculate total carbon emission

        # Splitting the uptime string and converting parts to appropriate types
        uptime_parts = uptime.split()
        uptime_hours = int(float(uptime_parts[0]))  # Convert float to int
        uptime_minutes = int(float(uptime_parts[2]))  # Convert float to int
        uptime_seconds = float(uptime_parts[4])  # Keep as float

        # Format the report data with HTML
        report_data += f"<b>Application Name: {name}</b><br>"
        report_data += f"<b>Uptime: </b>{uptime_hours} hours, {uptime_minutes} minutes, {uptime_seconds} seconds<br>"
        # Changing font color to the specified code for total carbon emission
        report_data += f"<b>Total Carbon: <font color='#00d75f'>{total_carbon} gCO2eq</font></b><br><br>"

    now = datetime.now()

    myobj = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "Carbon Emissions-Impact Framework",
        "themeColor": "00D75F",
        "title": "Carbon Emissions-Impact Framework",
        "sections": [
            {
                "title": "Top 10 Carbon Emitting Applications",
                "activityTitle": "Report Generated",
                "activitySubtitle": now.strftime("%d/%m/%Y %H:%M:%S"),
                "activityImage": "https://img.freepik.com/premium-vector/co2-emission-save-earth-from-climate-change-carbon-emissions-reduction-dioxide-zero-footprint_168129-2964.jpg",
                "facts": [
                    {
                        "name": "<b>Report Date</b>",
                        "value": now.strftime("%d/%m/%Y %H:%M:%S")
                    }
                ],
                "text": report_data
            }
        ],
    }

    webhook_url = <YOUR-WEBHOOK>

    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.post(webhook_url, json=myobj, headers=headers)

    if response.status_code == 200:
        print("Message sent successfully to Microsoft Teams!")
    else:
        print(f"Failed to send message. Status code: {response.status_code}")
        print(response.text)

createReport(data)
