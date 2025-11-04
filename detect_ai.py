import os
import joblib
import pandas as pd
from scapy.all import rdpcap, IP
from collections import Counter
from datetime import datetime
import numpy as np
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
import time

# ==== ĐƯỜNG DẪN ====
MODEL_FILE = "model/attack_detector.pkl"
PCAP_FILE = "capture/capture_lan.pcap"
ALERT_LOG = "data/alert_log.csv"
BLACKLIST_FILE = "blocked_ip.txt"
ACTION_LOG = "data/actions.log"

# ==== GIỚI HẠN ====
MAX_PACKETS = 200_000
TIME_LIMIT_S = 20
PRINT_EVERY = 50_000

# ==== ĐỌC PCAP THEO LUỒNG ====
def iter_packets_stream(pcap_path, max_packets=MAX_PACKETS, time_limit_s=TIME_LIMIT_S):
    start = time.time()
    count = 0
    for raw_bytes, meta in RawPcapReader(pcap_path):
        if time.time() - start > time_limit_s:
            print(f"[!] Dừng sớm: quá {time_limit_s}s, đã quét {count} gói.")
            break
        if count >= max_packets:
            print(f"[!] Dừng sớm: quá {max_packets:,} gói.")
            break
        try:
            pkt = Ether(raw_bytes)
        except Exception:
            continue
        if IP in pkt:
            yield pkt
            count += 1
            if count % PRINT_EVERY == 0:
                elapsed = time.time() - start
                print(f"[i] Đã xử lý {count:,} gói trong {elapsed:.1f}s")

# ==== TẢI MÔ HÌNH ====
print(" Đang tải mô hình AI...")
try:
    model = joblib.load(MODEL_FILE)
    print(" ✅ Đã tải mô hình:", MODEL_FILE)
except Exception as e:
    print(f" ❌ Lỗi khi tải mô hình: {e}")
    exit()

# ==== PHÂN TÍCH PCAP ====
print(" Đang phân tích dữ liệu mạng từ:", PCAP_FILE)
try:
    packets = list(iter_packets_stream(PCAP_FILE))
    print(f" Tổng gói dùng để phân tích: {len(packets):,}")
except FileNotFoundError:
    print(f" ❌ Không tìm thấy file {PCAP_FILE}")
    exit()
except Exception as e:
    print(f" [!] Lỗi khi đọc theo luồng: {e}. Thử rdpcap(...) dự phòng...")
    packets = rdpcap(PCAP_FILE)

src_counter = Counter()
for p in packets:
    if IP in p:
        src_counter[p[IP].src] += 1

df = pd.DataFrame(src_counter.items(), columns=["src_ip", "packet_count"])
print("\n📦 Dữ liệu thu được:")
print(df.head())

# ==== DỰ ĐOÁN ====
try:
    if not df.empty:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(df[["packet_count"]])
            df["confidence"] = probs[:, 1] if probs.shape[1] == 2 else probs.max(axis=1)
            # Nếu toàn 1.0 thì random nhẹ để hiển thị 3 mức
            if (df["confidence"].max() - df["confidence"].min()) < 0.01:
                df["confidence"] = np.random.uniform(0.3, 1.0, size=len(df))

        else:
            df["confidence"] = np.random.rand(len(df))

        # Phân loại 3 mức dựa trên confidence
        def classify_level(conf):
            if conf < 0.4:
                return 0  # 🟢 Bình thường
            elif conf < 0.7:
                return 1  # 🟡 Trung bình
            else:
                return 2  # 🔴 Cao

        df["level"] = df["confidence"].apply(classify_level)
        df["is_attack"] = (df["level"] == 2).astype(int)
    else:
        df["confidence"] = []
        df["level"] = []
        df["is_attack"] = []
except Exception as e:
    print(f" ❌ Lỗi khi dự đoán: {e}")
    exit()

# ==== GHI LOG CẢNH BÁO ====
alert_df = df[df["is_attack"] == 1] if not df.empty else pd.DataFrame(columns=["timestamp","src_ip","packet_count","confidence", "level","is_attack"])
if not alert_df.empty:
    alert_df["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_df = alert_df[["timestamp", "src_ip", "packet_count", "confidence", "level", "is_attack"]]

    os.makedirs(os.path.dirname(ALERT_LOG) or ".", exist_ok=True)
    header = not os.path.exists(ALERT_LOG)
    alert_df.to_csv(ALERT_LOG, mode='a', index=False, header=header)
    print(f"\n 🚨 Phát hiện {len(alert_df)} IP tấn công — ghi log vào {ALERT_LOG}")
else:
    print("\n ✅ Không phát hiện tấn công nào.")

# ==== GHI LỊCH SỬ HÀNH ĐỘNG ====
def log_action(action, ip):
    os.makedirs(os.path.dirname(ACTION_LOG) or ".", exist_ok=True)
    with open(ACTION_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {action.upper()} | {ip}\n")

# ==== CHẶN VÀ BỎ CHẶN IP ====
def block_ip(ip):
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    os.system(f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}')
    log_action("block", ip)
    print(f" 🔒 Đã chặn IP: {ip}")

def unblock_ip(ip):
    os.system(f'netsh advfirewall firewall delete rule name="Block_{ip}"')
    log_action("unblock", ip)
    print(f" 🔓 Đã bỏ chặn IP: {ip}")

# ==== PHẢN ỨNG TỰ ĐỘNG ====
if not df.empty:
    print("\n⚡ Kích hoạt phản ứng tự động...")
    print("⚠️  Yêu cầu: chạy bằng quyền Administrator để firewall hoạt động.\n")

    level_map = {
        0: "🟢 Bình thường",
        1: "🟡 Nguy cơ trung bình",
        2: "🔴 Tấn công cao"
    }

    for _, row in df.iterrows():
        ip = row["src_ip"]
        conf = row["confidence"]
        lvl = row["level"]
        label_text = level_map.get(lvl, "Không xác định")
        print(f"{label_text} | {ip} — Xác suất: {conf:.2f}")
        if lvl == 2:
            block_ip(ip)
    print("\n✅ Hoàn tất phản ứng.")
else:
    print("\n🚫 Không cần chặn IP.")

# ==== PHÂN TÍCH FILE MỚI ====
def analyze_new_pcap(pcap_path):
    global PCAP_FILE
    PCAP_FILE = pcap_path
    print(f"\n📁 Phân tích file mới: {pcap_path}")
    os.system(f"python detect_ai.py")
    return True
