from flask import Flask, render_template, jsonify, request, redirect
import pandas as pd
import json, os, subprocess, math
from datetime import datetime

app = Flask(__name__)

# === Cấu hình đường dẫn ===
MODEL_FILE = "model/attack_detector.pkl"
ALERT_LOG = "data/alert_log.csv"
BLACKLIST_FILE = "blocked_ip.txt"
ACTIONS_LOG = "data/actions.log"

# === Ghi log hành động ===
def log_action(action, ip, simulate):
    os.makedirs("data", exist_ok=True)
    with open(ACTIONS_LOG, 'a', encoding='utf-8') as f:
        f.write(f"{datetime.now()} | {action.upper()} | {ip} | Simulate={simulate}\n")

# === Giao diện Dashboard ===
@app.route("/dashboard")
def dashboard():
    alerts, blocked = [], []
    if os.path.exists(ALERT_LOG):
        df = pd.read_csv(ALERT_LOG)
        df = df.fillna(0)  # ⚡ Fix NaN
        alerts = df.to_dict(orient="records")

        # Loại bỏ giá trị NaN hoặc không hợp lệ thủ công nếu vẫn còn
        for a in alerts:
            for k, v in a.items():
                if isinstance(v, float) and (math.isnan(v) or v == float('inf') or v == float('-inf')):
                    a[k] = 0

    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE) as f:
            blocked = [x.strip() for x in f if x.strip()]

    if not alerts and not blocked:
        return "Chưa có dữ liệu phân tích!"
    return render_template("dashboard.html", alerts=alerts, blocked=blocked)

# === API: Lấy danh sách cảnh báo ===
@app.route('/api/alerts')
def api_alerts():
    if not os.path.exists(ALERT_LOG):
        return jsonify([])
    df = pd.read_csv(ALERT_LOG)
    df = df.fillna(0)  # ⚡ Thay NaN bằng 0
    records = df.to_dict(orient="records")

    # Loại bỏ NaN (trong trường hợp dữ liệu lỗi)
    for r in records:
        for k, v in r.items():
            if isinstance(v, float) and (math.isnan(v) or v == float('inf') or v == float('-inf')):
                r[k] = 0

    return jsonify(records)

# === API: Upload file .pcap để phân tích ===
@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "pcap_file" not in request.files:
            return "Không có file được gửi lên!", 400

        file = request.files["pcap_file"]
        if file.filename == "":
            return "Không có tên file!", 400

        save_path = os.path.join("capture", file.filename)
        os.makedirs("capture", exist_ok=True)
        file.save(save_path)

        # Gọi script detect_ai.py để phân tích
        try:
            subprocess.run(["python", "detect_ai.py", save_path], check=True)
        except Exception as e:
            return f"Lỗi khi chạy detect_ai.py: {e}", 500
        return redirect("/dashboard")
    return render_template("upload.html")

# === API: Danh sách IP bị chặn ===
@app.route('/api/blocked')
def api_blocked():
    if not os.path.exists(BLACKLIST_FILE):
        return jsonify([])
    with open(BLACKLIST_FILE) as f:
        blocked = [x.strip() for x in f if x.strip()]
    return jsonify(blocked)

# === API: Chặn IP ===
@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json(force=True)
    ip = data.get("ip")
    simulate = data.get("simulate", True)

    if not ip:
        return jsonify({"ok": False, "error": "Thiếu IP"})

    log_action("BLOCK", ip, simulate)

    # Ghi vào file blocked
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")

    if not simulate:
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                           check=True)
            msg = f"Đã CHẶN thật IP: {ip}"
        except Exception as e:
            msg = f"Lỗi khi chặn IP: {e}"
    else:
        msg = f"Giả lập chặn IP: {ip}"

    return jsonify({"ok": True, "message": msg})

# === API: Bỏ chặn IP ===
@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(force=True)
    ip = data.get("ip")
    simulate = data.get("simulate", True)

    if not ip:
        return jsonify({"ok": False, "error": "Thiếu IP"})

    log_action("UNBLOCK", ip, simulate)

    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE) as f:
            lines = [x.strip() for x in f if x.strip() and x.strip() != ip]
        with open(BLACKLIST_FILE, "w") as f:
            f.write("\n".join(lines))

    if not simulate:
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name=Block_{ip}"], check=True)
            msg = f"Đã BỎ CHẶN thật IP: {ip}"
        except Exception as e:
            msg = f"Lỗi khi bỏ chặn IP: {e}"
    else:
        msg = f"Giả lập bỏ chặn IP: {ip}"

    return jsonify({"ok": True, "message": msg})


if __name__ == "__main__":
    print("Lưu ý: cần chạy bằng quyền Administrator để chặn IP thật hoạt động.")
    app.run(debug=True)
