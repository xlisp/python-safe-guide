# Python Web安全代码文档 - White Belt 级别

## 目录
1. [跨站脚本攻击 (XSS)](#1-跨站脚本攻击-xss)
2. [SQL注入攻击](#2-sql注入攻击)
3. [跨站请求伪造 (CSRF)](#3-跨站请求伪造-csrf)
4. [文件上传漏洞](#4-文件上传漏洞)
5. [命令注入](#5-命令注入)
6. [路径遍历攻击](#6-路径遍历攻击)
7. [不安全的反序列化](#7-不安全的反序列化)
8. [弱密码策略](#8-弱密码策略)

---

## 1. 跨站脚本攻击 (XSS)

### 漏洞示例 ❌
```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # 危险：直接输出用户输入
    return f"<h1>搜索结果: {query}</h1>"

# 攻击载荷: /search?q=<script>alert('XSS')</script>
```

### 安全修复 ✅
```python
from flask import Flask, request, escape, render_template_string
from markupsafe import Markup

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # 安全：转义用户输入
    safe_query = escape(query)
    return f"<h1>搜索结果: {safe_query}</h1>"

# 或使用模板引擎自动转义
@app.route('/search_template')
def search_template():
    query = request.args.get('q', '')
    template = "<h1>搜索结果: {{ query }}</h1>"
    return render_template_string(template, query=query)
```

### 防护措施
- 使用模板引擎的自动转义功能
- 对所有用户输入进行HTML编码
- 实施内容安全策略 (CSP)
- 验证和过滤用户输入

---

## 2. SQL注入攻击

### 漏洞示例 ❌
```python
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 危险：直接拼接SQL语句
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    
    conn.close()
    return str(result)

# 攻击载荷: /user/1 OR 1=1--
```

### 安全修复 ✅
```python
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # 安全：使用参数化查询
        query = "SELECT * FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        
        conn.close()
        return str(result) if result else "用户不存在"
    except Exception as e:
        return "查询错误", 500

# 使用ORM的安全示例
from sqlalchemy import create_engine, text

def get_user_orm(user_id):
    engine = create_engine('sqlite:///users.db')
    with engine.connect() as conn:
        # 使用SQLAlchemy的参数绑定
        result = conn.execute(
            text("SELECT * FROM users WHERE id = :user_id"), 
            {"user_id": user_id}
        )
        return result.fetchone()
```

### 防护措施
- 始终使用参数化查询或预编译语句
- 使用ORM框架
- 对输入进行严格的类型验证
- 最小化数据库权限
- 定期进行安全审计

---

## 3. 跨站请求伪造 (CSRF)

### 漏洞示例 ❌
```python
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'your-secret-key'

@app.route('/transfer', methods=['POST'])
def transfer_money():
    if 'user_id' not in session:
        return "未登录", 401
    
    # 危险：没有CSRF保护
    to_account = request.form.get('to')
    amount = request.form.get('amount')
    
    # 执行转账操作
    return f"转账 {amount} 元到账户 {to_account}"
```

### 安全修复 ✅
```python
from flask import Flask, request, session
from flask_wtf.csrf import CSRFProtect
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key'
csrf = CSRFProtect(app)

# 方法1: 使用Flask-WTF的CSRF保护
@app.route('/transfer', methods=['POST'])
def transfer_money():
    if 'user_id' not in session:
        return "未登录", 401
    
    # CSRF token会自动验证
    to_account = request.form.get('to')
    amount = request.form.get('amount')
    
    return f"安全转账 {amount} 元到账户 {to_account}"

# 方法2: 手动CSRF token验证
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

@app.route('/manual_transfer', methods=['POST'])
def manual_transfer():
    if 'user_id' not in session:
        return "未登录", 401
    
    # 验证CSRF token
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return "CSRF token验证失败", 403
    
    to_account = request.form.get('to')
    amount = request.form.get('amount')
    
    return f"安全转账 {amount} 元到账户 {to_account}"
```

### 防护措施
- 使用CSRF tokens
- 验证HTTP Referer头
- 使用SameSite Cookie属性
- 对敏感操作使用双重验证

---

## 4. 文件上传漏洞

### 漏洞示例 ❌
```python
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    
    # 危险：没有文件类型验证
    filename = file.filename
    file.save(f"uploads/{filename}")
    
    return f"文件 {filename} 上传成功"

# 攻击者可上传: shell.php, malware.exe 等危险文件
```

### 安全修复 ✅
```python
from flask import Flask, request
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 允许的文件扩展名
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "没有文件", 400
    
    file = request.files['file']
    
    if file.filename == '':
        return "没有选择文件", 400
    
    # 安全检查
    if not allowed_file(file.filename):
        return "不允许的文件类型", 400
    
    # 检查文件大小
    if len(file.read()) > MAX_FILE_SIZE:
        return "文件太大", 400
    file.seek(0)  # 重置文件指针
    
    # 安全的文件名处理
    filename = secure_filename(file.filename)
    
    # 保存到安全目录
    upload_path = os.path.join('safe_uploads', filename)
    file.save(upload_path)
    
    return f"文件 {filename} 上传成功"
```

### 防护措施
- 验证文件类型和扩展名
- 限制文件大小
- 使用安全的文件名
- 将上传文件存储在非执行目录
- 扫描恶意软件

---

## 5. 命令注入

### 漏洞示例 ❌
```python
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    
    # 危险：直接执行用户输入
    result = os.system(f"ping -c 4 {host}")
    
    return f"Ping结果: {result}"

# 攻击载荷: /ping?host=127.0.0.1; rm -rf /
```

### 安全修复 ✅
```python
import subprocess
import re
from flask import Flask, request

app = Flask(__name__)

def is_valid_ip(ip):
    """验证IP地址格式"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def is_valid_hostname(hostname):
    """验证主机名格式"""
    pattern = r'^[a-zA-Z0-9.-]+$'
    return re.match(pattern, hostname) and len(hostname) <= 253

@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    
    # 输入验证
    if not (is_valid_ip(host) or is_valid_hostname(host)):
        return "无效的主机地址", 400
    
    try:
        # 安全：使用subprocess with shell=False
        result = subprocess.run(
            ['ping', '-c', '4', host], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        return f"Ping结果:\n{result.stdout}"
    except subprocess.TimeoutExpired:
        return "请求超时", 408
    except Exception as e:
        return "执行错误", 500
```

### 防护措施
- 避免使用shell命令执行
- 输入验证和白名单过滤
- 使用subprocess而不是os.system
- 设置执行超时
- 最小化程序权限

---

## 6. 路径遍历攻击

### 漏洞示例 ❌
```python
from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    
    # 危险：直接使用用户输入构造路径
    file_path = f"files/{filename}"
    
    return send_file(file_path)

# 攻击载荷: /download?file=../../../etc/passwd
```

### 安全修复 ✅
```python
from flask import Flask, request, send_file, abort
import os
from pathlib import Path

app = Flask(__name__)

# 安全的文件目录
SAFE_DIRECTORY = os.path.abspath("safe_files")

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    
    if not filename:
        abort(400)
    
    # 安全：规范化路径并验证
    safe_path = os.path.normpath(os.path.join(SAFE_DIRECTORY, filename))
    
    # 确保文件在安全目录内
    if not safe_path.startswith(SAFE_DIRECTORY):
        abort(403)
    
    # 检查文件是否存在
    if not os.path.isfile(safe_path):
        abort(404)
    
    return send_file(safe_path)

# 更安全的实现方式
@app.route('/secure_download')
def secure_download():
    filename = request.args.get('file')
    
    # 白名单方式：只允许特定文件
    allowed_files = {
        'readme.txt': 'readme.txt',
        'manual.pdf': 'user_manual.pdf',
        'image.jpg': 'sample.jpg'
    }
    
    if filename not in allowed_files:
        abort(404)
    
    actual_filename = allowed_files[filename]
    file_path = os.path.join(SAFE_DIRECTORY, actual_filename)
    
    return send_file(file_path)
```

### 防护措施
- 验证和规范化文件路径
- 使用白名单限制可访问文件
- 检查路径边界
- 避免直接使用用户输入构造路径

---

## 7. 不安全的反序列化

### 漏洞示例 ❌
```python
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/load_data', methods=['POST'])
def load_data():
    data = request.get_data()
    
    # 危险：直接反序列化用户数据
    obj = pickle.loads(data)
    
    return f"加载的对象: {obj}"

# 攻击者可构造恶意pickle数据执行任意代码
```

### 安全修复 ✅
```python
import json
import base64
from flask import Flask, request
from cryptography.fernet import Fernet

app = Flask(__name__)

# 生成密钥（实际应用中应安全存储）
key = Fernet.generate_key()
cipher_suite = Fernet(key)

@app.route('/load_data', methods=['POST'])
def load_data():
    try:
        data = request.get_json()
        
        if not data or 'payload' not in data:
            return "无效数据", 400
        
        # 安全方法1：使用JSON而不是pickle
        return f"加载的数据: {data['payload']}"
        
    except json.JSONDecodeError:
        return "JSON格式错误", 400

@app.route('/load_encrypted_data', methods=['POST'])
def load_encrypted_data():
    try:
        encrypted_data = request.get_data()
        
        # 安全方法2：使用加密的序列化数据
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        obj = json.loads(decrypted_data.decode())
        
        return f"解密的数据: {obj}"
        
    except Exception as e:
        return "解密失败", 400

# 安全的数据序列化类
class SafeSerializer:
    def __init__(self, secret_key):
        self.cipher = Fernet(secret_key)
    
    def serialize(self, obj):
        """安全序列化对象"""
        json_data = json.dumps(obj)
        encrypted_data = self.cipher.encrypt(json_data.encode())
        return base64.b64encode(encrypted_data).decode()
    
    def deserialize(self, data):
        """安全反序列化对象"""
        try:
            encrypted_data = base64.b64decode(data.encode())
            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except:
            raise ValueError("反序列化失败")
```

### 防护措施
- 避免使用pickle等不安全的序列化
- 使用JSON等安全的数据格式
- 对序列化数据进行加密和签名
- 验证反序列化的数据来源

---

## 8. 弱密码策略

### 漏洞示例 ❌
```python
from flask import Flask, request
import hashlib

app = Flask(__name__)

users = {}

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # 危险：弱密码哈希，无盐值
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    users[username] = password_hash
    return "注册成功"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username not in users:
        return "用户不存在", 404
    
    # 危险：使用MD5比较
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    if users[username] == password_hash:
        return "登录成功"
    else:
        return "密码错误", 401
```

### 安全修复 ✅
```python
from flask import Flask, request
import bcrypt
import re
from datetime import datetime, timedelta

app = Flask(__name__)

users = {}
failed_attempts = {}

def validate_password(password):
    """密码强度验证"""
    if len(password) < 8:
        return False, "密码至少8位"
    
    if not re.search(r"[A-Z]", password):
        return False, "密码必须包含大写字母"
    
    if not re.search(r"[a-z]", password):
        return False, "密码必须包含小写字母"
    
    if not re.search(r"\d", password):
        return False, "密码必须包含数字"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "密码必须包含特殊字符"
    
    return True, "密码强度合格"

def is_rate_limited(username):
    """检查登录频率限制"""
    if username in failed_attempts:
        attempts, last_attempt = failed_attempts[username]
        if attempts >= 5 and datetime.now() - last_attempt < timedelta(minutes=15):
            return True
    return False

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "用户名和密码不能为空", 400
    
    # 密码强度验证
    is_valid, message = validate_password(password)
    if not is_valid:
        return message, 400
    
    if username in users:
        return "用户已存在", 409
    
    # 安全：使用bcrypt哈希密码
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    users[username] = {
        'password': password_hash,
        'created_at': datetime.now(),
        'last_login': None
    }
    
    return "注册成功"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "用户名和密码不能为空", 400
    
    # 检查频率限制
    if is_rate_limited(username):
        return "登录尝试过于频繁，请15分钟后重试", 429
    
    if username not in users:
        return "用户名或密码错误", 401
    
    # 安全：使用bcrypt验证密码
    stored_password = users[username]['password']
    
    if bcrypt.checkpw(password.encode('utf-8'), stored_password):
        # 登录成功，清除失败记录
        if username in failed_attempts:
            del failed_attempts[username]
        
        users[username]['last_login'] = datetime.now()
        return "登录成功"
    else:
        # 记录失败尝试
        if username in failed_attempts:
            attempts, _ = failed_attempts[username]
            failed_attempts[username] = (attempts + 1, datetime.now())
        else:
            failed_attempts[username] = (1, datetime.now())
        
        return "用户名或密码错误", 401

@app.route('/change_password', methods=['POST'])
def change_password():
    username = request.form.get('username')
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    
    if not all([username, old_password, new_password]):
        return "缺少必要参数", 400
    
    if username not in users:
        return "用户不存在", 404
    
    # 验证旧密码
    stored_password = users[username]['password']
    if not bcrypt.checkpw(old_password.encode('utf-8'), stored_password):
        return "原密码错误", 401
    
    # 验证新密码强度
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return message, 400
    
    # 更新密码
    salt = bcrypt.gensalt()
    new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    users[username]['password'] = new_password_hash
    
    return "密码修改成功"
```

### 防护措施
- 使用强密码哈希算法（bcrypt, scrypt, Argon2）
- 实施密码复杂度要求
- 添加登录频率限制
- 使用盐值防止彩虹表攻击
- 定期强制密码更新

---

## 安全开发最佳实践

### 1. 输入验证
```python
import re
from flask import request

def validate_input(data, data_type, max_length=None):
    """通用输入验证函数"""
    if not data:
        return False, "数据不能为空"
    
    if max_length and len(data) > max_length:
        return False, f"数据长度不能超过{max_length}"
    
    patterns = {
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        'phone': r'^\d{11}$',
        'username': r'^[a-zA-Z0-9_]{3,20}$',
        'alphanumeric': r'^[a-zA-Z0-9]+$'
    }
    
    if data_type in patterns:
        if not re.match(patterns[data_type], data):
            return False, f"无效的{data_type}格式"
    
    return True, "验证通过"
```

### 2. 安全配置
```python
from flask import Flask
import os

app = Flask(__name__)

# 安全配置
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,  # 30分钟
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB
)

# 安全头设置
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### 3. 日志和监控
```python
import logging
from datetime import datetime
from flask import request, g

# 配置安全日志
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
handler = logging.FileHandler('security.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
security_logger.addHandler(handler)

def log_security_event(event_type, details):
    """记录安全事件"""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    
    security_logger.info(f"Security Event: {event_type} | IP: {client_ip} | UA: {user_agent} | Details: {details}")

# 使用示例
@app.route('/admin')
def admin_panel():
    if not is_admin():
        log_security_event("UNAUTHORIZED_ACCESS", "Attempted access to admin panel")
        return "Access denied", 403
    
    return "Admin panel"
```

## 安全测试清单

### White Belt 级别测试项目

1. **XSS测试**
   - [ ] 在所有输入字段测试 `<script>alert('XSS')</script>`
   - [ ] 测试反射型XSS和存储型XSS
   - [ ] 检查输出编码是否正确

2. **SQL注入测试**
   - [ ] 尝试 `' OR '1'='1` 等经典载荷
   - [ ] 测试数字型和字符型注入
   - [ ] 检查错误信息泄露

3. **文件上传测试**
   - [ ] 尝试上传恶意文件（.php, .jsp等）
   - [ ] 测试文件大小限制
   - [ ] 检查文件类型验证

4. **认证测试**
   - [ ] 测试弱密码
   - [ ] 检查登录频率限制
   - [ ] 测试会话管理

5. **授权测试**
   - [ ] 测试垂直权限提升
   - [ ] 测试水平权限提升
   - [ ] 检查敏感功能访问控制

---

这个文档涵盖了Web应用中最常见的安全漏洞和对应的防护措施。建议在实际开发中严格遵循这些安全实践，并定期进行安全测试和代码审计。
