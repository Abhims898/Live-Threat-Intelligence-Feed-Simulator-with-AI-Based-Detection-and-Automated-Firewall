from flask import Flask, render_template_string, send_file
import threading
import time
import random
import requests
import csv
from sklearn.ensemble import RandomForestClassifier
import numpy as np

app = Flask(__name__)

# -------------------------------
# CONFIG
# -------------------------------
API_KEY = "e53cfcee09803b581bb6e21597064b0e1cc32d2d92e1cccbcb3e516f4328b6736ed4b7465eab942c"   # 🔴 Put your AbuseIPDB API key

# -------------------------------
# GLOBAL DATA
# -------------------------------
threat_feed = set()
blocked_ips = set()
logs = []
alerts = []

total_requests = 0
blocked_count = 0
allowed_count = 0

running = False

# -------------------------------
# AI MODEL
# -------------------------------
X = np.array([[1,5],[2,4],[3,3],[10,1],[15,1],[20,0.5]])
y = [0,0,0,1,1,1]

model = RandomForestClassifier()
model.fit(X, y)

def predict_attack(req, delay):
    return model.predict([[req, delay]])[0] == 1

# -------------------------------
# LOG FUNCTION
# -------------------------------
def log(msg):
    logs.append(msg)
    if len(logs) > 100:
        logs.pop(0)

# -------------------------------
# ALERT FUNCTION
# -------------------------------
def add_alert(msg):
    alerts.append(msg)
    if len(alerts) > 10:
        alerts.pop(0)

# -------------------------------
# FETCH REAL THREAT INTEL
# -------------------------------
def fetch_threat_feed():
    url = "https://api.abuseipdb.com/api/v2/blacklist"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {"confidenceMinimum": 90}

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()

        count = 0
        for entry in data.get("data", [])[:20]:
            ip = entry.get("ipAddress")
            if ip:
                threat_feed.add(ip)
                count += 1

        log(f"[API] Loaded {count} malicious IPs")

    except Exception as e:
        log(f"[ERROR] API failed: {str(e)}")

# -------------------------------
# TRAFFIC SIMULATION (FIXED)
# -------------------------------
def simulate_traffic():
    global running, total_requests, blocked_count, allowed_count

    while running:
        total_requests += 1

        # 🔥 MIX: simulate real malicious traffic
        if random.random() < 0.3 and len(threat_feed) > 0:
            ip = random.choice(list(threat_feed))
        else:
            ip = f"192.168.1.{random.randint(1,150)}"

        log(f"[TRAFFIC] {ip}")

        # 🧠 AI Prediction (fixed logic)
        if predict_attack(random.randint(1,20), random.uniform(0.5,5)):
            add_alert("[AI ALERT] Suspicious traffic spike detected")

        # 🚨 Threat Detection
        if ip in threat_feed:
            if ip not in blocked_ips:
                blocked_ips.add(ip)
                blocked_count += 1
                log(f"[THREAT] {ip} → BLOCKED")
                add_alert(f"[CRITICAL] Blocked malicious IP: {ip}")
            else:
                log(f"[BLOCKED] {ip}")

        else:
            allowed_count += 1
            log(f"[SAFE] {ip}")

        time.sleep(2)

# -------------------------------
# EXPORT LOGS
# -------------------------------
def export_logs():
    filename = "logs.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Logs"])
        for l in logs:
            writer.writerow([l])
    return filename

# -------------------------------
# ROUTES
# -------------------------------
@app.route('/')
def home():
    return render_template_string("""
    <html>
    <head>
        <title>Cyber Dashboard</title>
        <meta http-equiv="refresh" content="3">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            body {background:#0d1117;color:#00ff9f;font-family:Consolas;}
            .card {background:#161b22;padding:15px;margin:10px;display:inline-block;width:30%;text-align:center;border-radius:10px;}
            a {color:#00ff9f;margin:10px;}
            .logs {background:black;height:200px;overflow:auto;padding:10px;}
            .alert {background:red;color:white;padding:10px;margin:5px;}
        </style>
    </head>

    <body>
        <h2>🛡️ Cyber Threat Intelligence Dashboard</h2>

        <div class="card">Total<br>{{total}}</div>
        <div class="card">Blocked<br>{{blocked}}</div>
        <div class="card">Allowed<br>{{allowed}}</div>

        <br>
        <a href="/start">Start</a>
        <a href="/stop">Stop</a>
        <a href="/update">Fetch Feed</a>
        <a href="/export">Export Logs</a>

        <h3>🚨 Alerts</h3>
        {% for a in alerts %}
            <div class="alert">{{a}}</div>
        {% endfor %}

        <h3>📊 Graph</h3>
        <div style="width:500px; margin:auto;">
           <canvas id="chart"></canvas>
        </div>

        <script>
        new Chart(document.getElementById('chart'), {
            type: 'bar',
            data: {
                labels: ['Total','Allowed','Blocked'],
                datasets: [{
                    label: 'Stats',
                    data: [{{total}},{{allowed}},{{blocked}}]
                }]
            }
        });
        </script>

        <h3>Logs</h3>
        <div class="logs">
        {% for log in logs %}
            <p>{{log}}</p>
        {% endfor %}
        </div>

    </body>
    </html>
    """, logs=logs, alerts=alerts, total=total_requests, blocked=blocked_count, allowed=allowed_count)


@app.route('/start')
def start():
    global running
    if not running:
        running = True
        threading.Thread(target=simulate_traffic, daemon=True).start()
        log("[SYSTEM] Started")
    return "Started <a href='/'>Back</a>"


@app.route('/stop')
def stop():
    global running
    running = False
    log("[SYSTEM] Stopped")
    return "Stopped <a href='/'>Back</a>"


@app.route('/update')
def update():
    fetch_threat_feed()
    return "Feed Updated <a href='/'>Back</a>"


@app.route('/export')
def export():
    file = export_logs()
    return send_file(file, as_attachment=True)


# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)