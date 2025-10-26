import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import os

print("🚀 Bắt đầu huấn luyện mô hình DDoS Detector...")

# Kiểm tra file dữ liệu
DATA_FILE = "data/lan_from_wireshark.csv"
if not os.path.exists(DATA_FILE):
    print(f"❌ Không tìm thấy file dữ liệu: {DATA_FILE}")
    exit()

# Đọc dữ liệu
data = pd.read_csv(DATA_FILE)
print(f"📊 Đã đọc {len(data)} dòng dữ liệu từ {DATA_FILE}")

# Nếu chưa có cột packet_count thì tự sinh ngẫu nhiên
if "packet_count" not in data.columns:
    data["packet_count"] = np.random.randint(100, 2000, size=len(data))

# Giả lập gán nhãn: 0 = bình thường, 1 = tấn công
data["label"] = (data["packet_count"] > 1200).astype(int)

# Chọn đặc trưng
X = data[["packet_count"]]
y = data["label"]

# Chia dữ liệu
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Huấn luyện mô hình
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Đánh giá độ chính xác
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Accuracy: {acc:.2f}")

# Lưu mô hình
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/attack_detector.pkl")
print("📦 Đã lưu mô hình vào model/attack_detector.pkl")
