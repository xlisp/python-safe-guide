一个基于静态分析的Python安全检查工具，它可以扫描项目中的Python代码并识别常见的安全问题。

我为您创建了一个功能完整的Python安全静态分析工具。这个工具可以扫描Python项目并识别常见的安全漏洞。

## 🔍 工具特性

### 支持的安全检查规则：

1. **SQL注入检测** - 识别可能的SQL注入漏洞
2. **命令注入检测** - 检测危险的系统命令执行
3. **弱哈希算法检测** - 识别MD5、SHA1等弱哈希算法
4. **硬编码密钥检测** - 发现硬编码的密码、API密钥等
5. **不安全反序列化** - 检测pickle等不安全的反序列化
6. **不安全随机数** - 识别在安全上下文中使用的弱随机数生成器

### 主要功能：

- **AST静态分析** - 基于抽象语法树进行精确分析
- **多种输出格式** - 支持文本和JSON格式报告
- **严重程度分级** - CRITICAL、HIGH、MEDIUM、LOW、INFO
- **详细报告** - 包含文件位置、代码片段、修复建议
- **递归扫描** - 支持扫描整个项目目录
- **可扩展架构** - 易于添加新的安全规则

## 🚀 使用方法

### 1. 基本用法
```bash
# 扫描单个文件
python security_scanner.py example.py

# 扫描目录（递归）
python security_scanner.py /path/to/project -r

# 生成JSON格式报告
python security_scanner.py project/ -f json -o report.json
```

### 2. 命令行参数
- `path` - 要扫描的文件或目录路径
- `-r, --recursive` - 递归扫描子目录
- `-f, --format` - 输出格式（text/json）
- `-o, --output` - 输出文件路径

### 3. 测试功能
工具包含一个测试文件生成器，运行时会自动创建包含各种安全问题的测试文件：

```bash
python security_scanner.py  # 创建测试文件
python security_scanner.py vulnerable_test.py  # 扫描测试文件
```

## 📊 报告示例

### 文本格式报告：
```
🔍 Python安全扫描报告
==================================================
总计发现 6 个安全问题

🔴 CRITICAL: 0 个
🟠 HIGH: 4 个
🟡 MEDIUM: 2 个
🔵 LOW: 0 个
⚪ INFO: 0 个

==================================================
详细问题列表:
==================================================

🔍 HIGH 级别问题:
------------------------------

1. 潜在的SQL注入漏洞
   文件: vulnerable_test.py
   位置: 第 12 行, 第 4 列
   规则: SQL_INJECTION
   描述: 检测到可能的SQL注入漏洞，应使用参数化查询
   代码: query = f"SELECT * FROM users WHERE id = {user_id}"
   建议: 使用参数化查询，如: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
```

## 🔧 扩展性

工具采用规则
