import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier
import joblib
import os

print(" Bắt đầu huấn luyện mô hình DDoS Detector...")

# Kiểm tra file dữ liệu
DATA_FILE = "data/lan_from_wireshark.csv"
if not os.path.exists(DATA_FILE) or os.path.getsize(DATA_FILE) == 0:
    print("⚠️ File dữ liệu trống hoặc không tồn tại, tạo dữ liệu giả lập...")
    os.makedirs("data", exist_ok=True)
    df = pd.DataFrame({"packet_count": np.random.randint(100, 2000, 500)})
    df.to_csv(DATA_FILE, index=False)   
    exit()

# Đọc dữ liệu
data = pd.read_csv(DATA_FILE)
print(f" Đã đọc {len(data)} dòng dữ liệu từ {DATA_FILE}")

# Nếu chưa có cột packet_count thì tự sinh ngẫu nhiên
if "packet_count" not in data.columns:
    data["packet_count"] = np.random.randint(100, 2000, size=len(data))

# Gán nhãn 3 mức độ: 0 = bình thường, 1 = nguy cơ, 2 = tấn công cao
def get_label(x):
    if x < 800:
        return 0  # bình thường
    elif x < 1500:
        return 1  # nguy cơ
    else:
        return 2  # tấn công cao

data["label"] = data["packet_count"].apply(get_label)


# Chọn đặc trưng
X = data[["packet_count"]]
y = data["label"]

# Chia dữ liệu
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Huấn luyện mô hình
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

df = pd.DataFrame(data)
model = DecisionTreeClassifier(random_state=42)
model.fit(df[["packet_count"]], df["label"])


# Đánh giá độ chính xác
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Accuracy: {acc:.2f}")

# Lưu mô hình
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/attack_detector.pkl")
print("📦 Đã lưu mô hình vào model/attack_detector.pkl")
