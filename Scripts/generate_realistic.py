#!/usr/bin/env python3

import random
import datetime
import pandas as pd
import numpy as np

random.seed(42)
np.random.seed(42)

INTERNAL_IPS = [
    "192.168.1.50", "192.168.1.75", "10.0.0.25",
    "192.168.1.100", "192.168.1.30", "10.0.0.15"
]

EXTERNAL_LEGIT_IPS = [
    "82.64.12.33",
    "90.112.45.67",
    "78.193.22.100"
]

ATTACK_IPS = [
    "185.220.101.45", "42.96.145.33", "165.232.189.42",
    "103.45.67.89",   "159.89.166.45", "45.142.212.61",
    "194.165.16.72",  "91.108.4.0",    "178.20.55.18",
    "5.188.206.14",   "193.32.162.45", "185.234.218.33"
]

LEGIT_USERS = ["admin", "devops", "deploy", "backup", "monitoring", "analyst"]
ATTACK_USERS = [
    "root", "admin", "user", "test", "oracle",
    "postgres", "mysql", "git", "ubuntu", "centos", "pi"
]

rows = []

for _ in range(42500):
    hour = random.randint(7, 19)
    ip = random.choice(INTERNAL_IPS)
    user = random.choice(LEGIT_USERS)
    port = random.randint(40000, 65000)
    method = random.choices(["publickey", "password"], weights=[70, 30])[0]
    rows.append({
        "hour": hour,
        "src_ip": ip,
        "username": user,
        "src_port": port,
        "result": "Accepted",
        "auth_method": method,
        "label": 0
    })

for _ in range(4000):
    hour = random.randint(7, 22)
    ip = random.choices(
        INTERNAL_IPS + EXTERNAL_LEGIT_IPS,
        weights=[60, 60, 60, 60, 60, 60, 20, 20, 20]
    )[0]
    user = random.choice(LEGIT_USERS)
    port = random.randint(40000, 65000)
    rows.append({
        "hour": hour,
        "src_ip": ip,
        "username": user,
        "src_port": port,
        "result": "Failed",
        "auth_method": "password",
        "label": 0
    })

for _ in range(2500):
    hour = random.choices(
        list(range(24)),
        weights=[8, 8, 8, 8, 6, 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 4, 5, 6, 7, 8, 8, 8]
    )[0]
    ip = random.choice(ATTACK_IPS)
    user = random.choice(ATTACK_USERS)
    port = random.randint(1024, 65000)
    success = random.random() < 0.03
    rows.append({
        "hour": hour,
        "src_ip": ip,
        "username": user,
        "src_port": port,
        "result": "Accepted" if success else "Failed",
        "auth_method": "password",
        "label": 1
    })

for _ in range(1000):
    hour = random.randint(8, 18)
    ip = random.choice(ATTACK_IPS)
    user = random.choice(LEGIT_USERS)
    port = random.randint(40000, 65000)
    rows.append({
        "hour": hour,
        "src_ip": ip,
        "username": user,
        "src_port": port,
        "result": "Failed",
        "auth_method": "password",
        "label": 1
    })

random.shuffle(rows)
df = pd.DataFrame(rows)

base = datetime.datetime(2024, 1, 15)
timestamps = [
    base
    + datetime.timedelta(hours=r["hour"], minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    for r in rows
]
df["timestamp"] = timestamps
df = df.sort_values("timestamp").reset_index(drop=True)

months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

with open("/home/adminml/auth_realistic.log", "w") as f:
    for _, row in df.iterrows():
        ts = pd.to_datetime(row["timestamp"])
        mon = months[ts.month - 1]
        day = f"{ts.day:2d}"
        time_str = f"{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d}"
        pid = random.randint(10000, 20000)
        f.write(
            f"{mon} {day} {time_str} server sshd[{pid}]: "
            f"{row['result']} {row['auth_method']} for "
            f"{row['username']} from {row['src_ip']} "
            f"port {row['src_port']} ssh2\n"
        )

print("Log généré : /home/adminml/auth_realistic.log")
df.to_csv("/home/adminml/ssh_dataset.csv", index=False)

print(f"Dataset généré : {len(df)} événements")
print(df["label"].value_counts())
print(f"Taux attaque : {df['label'].mean()*100:.1f}%")
print("\nDistribution result/label (bruit visible) :")
print(pd.crosstab(df["result"], df["label"]))
