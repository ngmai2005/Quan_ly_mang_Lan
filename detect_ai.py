import os
import joblib
import pandas as pd
from scapy.all import rdpcap, IP
from collections import Counter
from datetime import datetime
import numpy as np

# [ADD] bổ sung import cho đọc theo luồng
from scapy.utils import RawPcapReader  # [ADD]
from scapy.layers.l2 import Ether      # [ADD]
import time                            # [ADD]

# ==== ĐƯỜNG DẪN ====
MODEL_FILE = "model/attack_detector.pkl"
PCAP_FILE = "capture/capture_lan.pcap"
ALERT_LOG = "data/alert_log.csv"
BLACKLIST_FILE = "blocked_ip.txt"
ACTION_LOG = "data/actions.log"

# [ADD] cấu hình giới hạn khi đọc PCAP lớn
MAX_PACKETS  = 200_000   # giới hạn số gói tối đa (tùy chỉnh) [ADD]
TIME_LIMIT_S = 20        # giới hạn thời gian phân tích (giây)   [ADD]
PRINT_EVERY  = 50_000    # nhịp in tiến độ                        [ADD]

# [ADD] Đọc PCAP theo luồng để tránh đầy RAM/treo rdpcap
def iter_packets_stream(pcap_path, max_packets=MAX_PACKETS, time_limit_s=TIME_LIMIT_S):
    """
    Đọc PCAP theo luồng, dừng theo ngưỡng số gói hoặc thời gian để tránh chậm/treo.
    Chỉ yield gói có lớp IP để giảm chi phí parse.
    """
    start = time.time()
    count = 0
    for raw_bytes, meta in RawPcapReader(pcap_path):
        # dừng theo thời gian
        if time.time() - start > time_limit_s:
            print(f"[!] Dừng sớm: quá {time_limit_s}s, đã quét {count} gói.")
            break
        # dừng theo số gói
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

# ==== KHỞI TẠO MÔ HÌNH ====
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
    # OLD: packets = rdpcap(PCAP_FILE)
    # [ADD] Thay bằng đọc theo luồng, sau đó gom list để giữ nguyên luồng xử lý phía dưới
    packets = list(iter_packets_stream(PCAP_FILE))  # [ADD]
    print(f"[✓] Tổng gói dùng để phân tích: {len(packets):,}")  # [ADD]
except FileNotFoundError:
    print(f" ❌ Không tìm thấy file {PCAP_FILE}")
    exit()
except KeyboardInterrupt:
    print(" ❌ Đã hủy bởi người dùng (KeyboardInterrupt).")
    exit()
except Exception as e:
    # fallback an toàn: nếu RawPcapReader gặp lỗi hiếm, thử rdpcap như cũ (có thể chậm)
    print(f" [!] Lỗi khi đọc theo luồng: {e}. Thử rdpcap(...) dự phòng...")
    packets = rdpcap(PCAP_FILE)

src_counter = Counter()
for p in packets:
    if IP in p:
        src_counter[p[IP].src] += 1

df = pd.DataFrame(src_counter.items(), columns=["src_ip", "packet_count"])
print("\n📦 Dữ liệu thu được:")
print(df.head())

# === Thêm dự đoán + confidence (độ nguy hiểm) ===
try:
    if not df.empty:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(df[["packet_count"]])
            df["confidence"] = probs[:, 1]  # Xác suất tấn công
        else:
            df["confidence"] = np.random.rand(len(df))  # mô phỏng nếu model không có predict_proba

        df["is_attack"] = (df["confidence"] > 0.7).astype(int)
    else:
        # [ADD] bảo vệ khi không có gói IP nào
        df["confidence"] = []
        df["is_attack"] = []
except Exception as e:
    print(f" ❌ Lỗi khi dự đoán: {e}")
    exit()

# === Ghi log cảnh báo ===
alert_df = df[df["is_attack"] == 1] if not df.empty else pd.DataFrame(columns=["timestamp","src_ip","packet_count","confidence","is_attack"])
if not alert_df.empty:
    alert_df["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_df = alert_df[["timestamp", "src_ip", "packet_count", "confidence", "is_attack"]]

    os.makedirs(os.path.dirname(ALERT_LOG) or ".", exist_ok=True)  # [ADD] đảm bảo thư mục tồn tại
    header = not os.path.exists(ALERT_LOG)
    alert_df.to_csv(ALERT_LOG, mode='a', index=False, header=header)
    print(f"\n🚨 Phát hiện {len(alert_df)} IP tấn công — ghi log vào {ALERT_LOG}")
else:
    print("\n✅ Không phát hiện tấn công nào.")

# === Ghi lịch sử hành động ===
def log_action(action, ip):
    """Ghi hành động của admin (block/unblock)"""
    os.makedirs(os.path.dirname(ACTION_LOG) or ".", exist_ok=True)  # [ADD]
    with open(ACTION_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {action.upper()} | {ip}\n")

# === Chặn IP tự động ===
def block_ip(ip):
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")
    os.system(f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}')
    log_action("block", ip)
    print(f" 🔒 Đã chặn IP: {ip}")

# === Bỏ chặn IP (tuỳ chọn nếu muốn thêm) ===
def unblock_ip(ip):
    os.system(f'netsh advfirewall firewall delete rule name="Block_{ip}"')
    log_action("unblock", ip)
    print(f" 🔓 Đã bỏ chặn IP: {ip}")

# === Phản ứng tự động ===
if not alert_df.empty:
    print("\n⚡ Kích hoạt phản ứng tự động...")
    print("⚠️ Yêu cầu: chạy script bằng quyền Administrator để firewall hoạt động.\n")
    for _, row in alert_df.iterrows():
        ip = row["src_ip"]
        conf = row["confidence"]
        color = "🟢" if conf < 0.5 else "🟡" if conf < 0.8 else "🔴"
        print(f"{color} {ip} — Mức độ nguy hiểm: {conf:.2f}")
        block_ip(ip)
    print("\n✅ Hoàn tất phản ứng.")
else:
    print("\n🚫 Không cần chặn IP.")

# ==== 🔄 HÀM HỖ TRỢ CHẠY LẠI PHÂN TÍCH ====
def analyze_new_pcap(pcap_path):
    """Phân tích file PCAP mới upload"""
    global PCAP_FILE
    PCAP_FILE = pcap_path
    print(f"\n📁 Phân tích file mới: {pcap_path}")
    os.system(f"python detect_ai.py")
    return True
