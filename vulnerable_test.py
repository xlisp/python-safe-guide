# 测试文件 - 包含各种安全问题

import os
import sqlite3
import hashlib
import pickle
import random

# SQL注入漏洞
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # 危险
    cursor.execute(query)
    return cursor.fetchone()

# 命令注入漏洞
def ping_host(hostname):
    result = os.system(f"ping -c 4 {hostname}")  # 危险
    return result

# 弱哈希算法
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # 危险

# 硬编码密钥
SECRET_KEY = "supersecretkey123456789"  # 危险
API_TOKEN = "abc123def456ghi789"  # 危险

# 不安全反序列化
def load_data(data):
    return pickle.loads(data)  # 危险

# 不安全随机数
def generate_session_token():
    return str(random.randint(100000, 999999))  # 危险 - 用于安全目的

# 正常代码（不会触发警告）
def safe_function():
    return "This is safe"
