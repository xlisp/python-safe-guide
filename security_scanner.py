#!/usr/bin/env python3
"""
Python安全静态分析工具
扫描Python项目中的安全漏洞和不安全的代码模式
"""

import ast
import os
import re
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    """安全问题严重程度"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityIssue:
    """安全问题数据结构"""
    file_path: str
    line_number: int
    column: int
    rule_id: str
    severity: SeverityLevel
    title: str
    description: str
    code_snippet: str
    recommendation: str


class SecurityRule:
    """安全规则基类"""
    
    def __init__(self, rule_id: str, severity: SeverityLevel, title: str, description: str):
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.description = description
    
    def check(self, node: ast.AST, source_lines: List[str]) -> List[SecurityIssue]:
        """检查AST节点是否存在安全问题"""
        raise NotImplementedError


class SQLInjectionRule(SecurityRule):
    """SQL注入检测规则"""
    
    def __init__(self):
        super().__init__(
            "SQL_INJECTION",
            SeverityLevel.HIGH,
            "潜在的SQL注入漏洞",
            "检测到可能的SQL注入漏洞，应使用参数化查询"
        )
    
    def check(self, node: ast.AST, source_lines: List[str]) -> List[SecurityIssue]:
        issues = []
        
        if isinstance(node, ast.Call):
            # 检查execute方法调用
            if (isinstance(node.func, ast.Attribute) and 
                node.func.attr in ['execute', 'executemany']):
                
                # 检查是否使用字符串格式化或拼接
                if node.args:
                    first_arg = node.args[0]
                    if self._is_string_formatting(first_arg):
                        issues.append(self._create_issue(node, source_lines))
        
        return issues
    
    def _is_string_formatting(self, node: ast.AST) -> bool:
        """检查是否使用了字符串格式化"""
        return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) or
                isinstance(node, ast.JoinedStr) or  # f-string
                isinstance(node, ast.Call) and 
                isinstance(node.func, ast.Attribute) and 
                node.func.attr in ['format'])
    
    def _create_issue(self, node: ast.AST, source_lines: List[str]) -> SecurityIssue:
        code_snippet = source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ""
        return SecurityIssue(
            file_path="",  # 将在扫描时填充
            line_number=node.lineno,
            column=node.col_offset,
            rule_id=self.rule_id,
            severity=self.severity,
            title=self.title,
            description=self.description,
            code_snippet=code_snippet,
            recommendation="使用参数化查询，如: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        )


class CommandInjectionRule(SecurityRule):
    """命令注入检测规则"""
    
    def __init__(self):
        super().__init__(
            "COMMAND_INJECTION",
            SeverityLevel.HIGH,
            "潜在的命令注入漏洞",
            "检测到可能的命令注入漏洞"
        )
        self.dangerous_functions = [
            'os.system', 'os.popen', 'subprocess.call', 'subprocess.run',
            'subprocess.Popen', 'commands.getoutput', 'eval', 'exec'
        ]
    
    def check(self, node: ast.AST, source_lines: List[str]) -> List[SecurityIssue]:
        issues = []
        
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node.func)
            if func_name in self.dangerous_functions:
                # 检查是否直接使用用户输入
                if self._has_user_input(node):
                    issues.append(self._create_issue(node, source_lines, func_name))
        
        return issues
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """获取函数名"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
        return ""
    
    def _has_user_input(self, node: ast.Call) -> bool:
        """检查是否包含用户输入（简化检查）"""
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                return True  # 字符串拼接可能包含用户输入
            elif isinstance(arg, ast.JoinedStr):
                return True  # f-string可能包含用户输入
        return False
    
    def _create_issue(self, node: ast.AST, source_lines: List[str], func_name: str) -> SecurityIssue:
        code_snippet = source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ""
        return SecurityIssue(
            file_path="",
            line_number=node.lineno,
            column=node.col_offset,
            rule_id=self.rule_id,
            severity=self.severity,
            title=self.title,
            description=f"使用了危险函数 {func_name}",
            code_snippet=code_snippet,
            recommendation="验证用户输入，使用subprocess.run()并设置shell=False"
        )


class WeakHashingRule(SecurityRule):
    """弱哈希算法检测规则"""
    
    def __init__(self):
        super().__init__(
            "WEAK_HASHING",
            SeverityLevel.MEDIUM,
            "使用了弱哈希算法",
            "检测到使用了不安全的哈希算法"
        )
        self.weak_algorithms = ['md5', 'sha1']
    
    def check(self, node: ast.AST, source_lines: List[str]) -> List[SecurityIssue]:
        issues = []
        
        if isinstance(node, ast.Call):
            # 检查hashlib调用
            if (isinstance(node.func, ast.Attribute) and 
                isinstance(node.func.value, ast.Name) and 
                node.func.value.id == 'hashlib' and 
                node.func.attr in self.weak_algorithms):
                
                issues.append(self._create_issue(node, source_lines, node.func.attr))
            
            # 检查直接调用
            elif (isinstance(node.func, ast.Name) and 
                  node.func.id in self.weak_algorithms):
                issues.append(self._create_issue(node, source_lines, node.func.id))
        
        return issues
    
    def _create_issue(self, node: ast.AST, source_lines: List[str], algorithm: str) -> SecurityIssue:
        code_snippet = source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ""
        return SecurityIssue(
            file_path="",
            line_number=node.lineno,
            column=node.col_offset,
            rule_id=self.rule_id,
            severity=self.severity,
            title=self.title,
            description=f"使用了弱哈希算法: {algorithm}",
            code_snippet=code_snippet,
            recommendation="使用更安全的哈希算法，如SHA-256、SHA-3或bcrypt（用于密码）"
        )


class HardcodedSecretRule(SecurityRule):
    """硬编码密钥检测规则"""
    
    def __init__(self):
        super().__init__(
            "HARDCODED_SECRET",
            SeverityLevel.HIGH,
            "硬编码的敏感信息",
            "检测到硬编码的密码、密钥或其他敏感信息"
        )
        self.secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{8,}["\']', "密码"),
            (r'secret\s*=\s*["\'][^"\']{16,}["\']', "密钥"),
            (r'api_key\s*=\s*["\'][^"\']{16,}["\']', "API密钥"),
            (r'token\s*=\s*["\'][^"\']{16,}["\']', "访问令牌"),
            (r'private_key\s*=\s*["\'][^"\']{32,}["\']', "私钥"),
        ]
    
    def check(self, node: ast.AST, source_lines: List[str]) -> List[SecurityIssue]:
        issues = []
        
        if isinstance(node, ast.Assign):
            # 检查赋值语句
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if isinstance(node.value, ast.Str):
                        value = node.value.s
                        if self._is_potential_secret(var_name, value):
                            issues.append(self._create_issue(node, source_lines, var_name))
        
        return issues
    
    def _is_potential_secret(self, var_name: str, value: str) -> bool:
        """检查是否是潜在的敏感信息"""
        sensitive_keywords = ['password', 'secret', 'key', 'token', 'credential']
        
        # 检查变量名
        if any(keyword in var_name for keyword in sensitive_keywords):
            # 检查值的长度和复杂性
            if len(value) >= 8 and not value.lower() in ['password', 'secret', 'example']:
                return True
        
        return False
    
    def _create_issue(self, node: ast.AST, source_lines: List[str], var_name: str) -> SecurityIssue:
        code_snippet = source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ""
        return SecurityIssue(
            file_path="",
            line_number=node.lineno,
            column=node.col_offset,
            rule_id=self.rule_id,
            severity=self.severity,
            title=self.title,
            description=f"检测到硬编码的敏感变量: {var_name}",
            code_snippet=code_snippet,
            recommendation="使用环境变量或配置文件存储敏感信息"
        )


class DeserializationRule(SecurityRule):
    """不安全反序列化检测规则"""
    
    def __init__(self):
        super().__init__(
            "UNSAFE_DESERIALIZATION",
            SeverityLevel.HIGH,
            "不安全的反序列化",
            "检测到不安全的反序列化操作"
        )
        self.dangerous_functions = ['pickle.loads', 'pickle.load', 'cPickle.loads', 'cPickle.load']
    
    def check(self, node: ast.AST, source_lines: List[str]) -> List[SecurityIssue]:
        issues = []
        
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node.func)
            if func_name in self.dangerous_functions:
                issues.append(self._create_issue(node, source_lines, func_name))
        
        return issues
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """获取函数名"""
        if isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
        return ""
    
    def _create_issue(self, node: ast.AST, source_lines: List[str], func_name: str) -> SecurityIssue:
        code_snippet = source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ""
        return SecurityIssue(
            file_path="",
            line_number=node.lineno,
            column=node.col_offset,
            rule_id=self.rule_id,
            severity=self.severity,
            title=self.title,
            description=f"使用了不安全的反序列化函数: {func_name}",
            code_snippet=code_snippet,
            recommendation="使用JSON或其他安全的序列化格式，避免使用pickle处理不可信数据"
        )


class InsecureRandomRule(SecurityRule):
    """不安全随机数检测规则"""
    
    def __init__(self):
        super().__init__(
            "INSECURE_RANDOM",
            SeverityLevel.MEDIUM,
            "使用了不安全的随机数生成器",
            "检测到使用了密码学上不安全的随机数生成器"
        )
        self.insecure_functions = ['random.random', 'random.randint', 'random.choice']
    
    def check(self, node: ast.AST, source_lines: List[str]) -> List[SecurityIssue]:
        issues = []
        
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node.func)
            if func_name in self.insecure_functions:
                # 检查上下文是否涉及安全用途
                if self._is_security_context(source_lines, node.lineno):
                    issues.append(self._create_issue(node, source_lines, func_name))
        
        return issues
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """获取函数名"""
        if isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
        return ""
    
    def _is_security_context(self, source_lines: List[str], line_no: int) -> bool:
        """检查是否在安全相关的上下文中"""
        security_keywords = ['password', 'token', 'key', 'secret', 'session', 'csrf']
        
        # 检查前后几行是否包含安全相关关键词
        start = max(0, line_no - 5)
        end = min(len(source_lines), line_no + 5)
        
        for i in range(start, end):
            line = source_lines[i].lower()
            if any(keyword in line for keyword in security_keywords):
                return True
        
        return False
    
    def _create_issue(self, node: ast.AST, source_lines: List[str], func_name: str) -> SecurityIssue:
        code_snippet = source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ""
        return SecurityIssue(
            file_path="",
            line_number=node.lineno,
            column=node.col_offset,
            rule_id=self.rule_id,
            severity=self.severity,
            title=self.title,
            description=f"在安全上下文中使用了不安全的随机函数: {func_name}",
            code_snippet=code_snippet,
            recommendation="使用secrets模块生成密码学安全的随机数"
        )


class PythonSecurityScanner:
    """Python安全扫描器主类"""
    
    def __init__(self):
        self.rules = [
            SQLInjectionRule(),
            CommandInjectionRule(),
            WeakHashingRule(),
            HardcodedSecretRule(),
            DeserializationRule(),
            InsecureRandomRule(),
        ]
        self.issues = []
    
    def scan_file(self, file_path: str) -> List[SecurityIssue]:
        """扫描单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                source_lines = content.splitlines()
            
            # 解析AST
            tree = ast.parse(content, filename=file_path)
            
            file_issues = []
            
            # 遍历AST节点
            for node in ast.walk(tree):
                for rule in self.rules:
                    issues = rule.check(node, source_lines)
                    for issue in issues:
                        issue.file_path = file_path
                        file_issues.append(issue)
            
            return file_issues
            
        except SyntaxError as e:
            print(f"语法错误 {file_path}: {e}")
            return []
        except Exception as e:
            print(f"扫描文件 {file_path} 时出错: {e}")
            return []
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[SecurityIssue]:
        """扫描目录"""
        all_issues = []
        
        path = Path(directory)
        
        if recursive:
            python_files = path.rglob("*.py")
        else:
            python_files = path.glob("*.py")
        
        for file_path in python_files:
            # 跳过虚拟环境和测试文件
            if any(part in str(file_path) for part in ['venv', 'env', '__pycache__', '.git']):
                continue
            
            print(f"扫描文件: {file_path}")
            issues = self.scan_file(str(file_path))
            all_issues.extend(issues)
        
        return all_issues
    
    def generate_report(self, issues: List[SecurityIssue], format_type: str = "text") -> str:
        """生成扫描报告"""
        if format_type == "json":
            return self._generate_json_report(issues)
        else:
            return self._generate_text_report(issues)
    
    def _generate_text_report(self, issues: List[SecurityIssue]) -> str:
        """生成文本格式报告"""
        if not issues:
            return "✅ 未发现安全问题！"
        
        # 按严重程度分组
        severity_groups = {}
        for issue in issues:
            if issue.severity not in severity_groups:
                severity_groups[issue.severity] = []
            severity_groups[issue.severity].append(issue)
        
        report = []
        report.append("🔍 Python安全扫描报告")
        report.append("=" * 50)
        report.append(f"总计发现 {len(issues)} 个安全问题\n")
        
        # 统计信息
        for severity in SeverityLevel:
            count = len(severity_groups.get(severity, []))
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
                report.append(f"{emoji.get(severity.value, '•')} {severity.value}: {count} 个")
        
        report.append("\n" + "=" * 50)
        report.append("详细问题列表:")
        report.append("=" * 50)
        
        # 按严重程度排序输出
        severity_order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]
        
        for severity in severity_order:
            if severity in severity_groups:
                report.append(f"\n🔍 {severity.value} 级别问题:")
                report.append("-" * 30)
                
                for i, issue in enumerate(severity_groups[severity], 1):
                    report.append(f"\n{i}. {issue.title}")
                    report.append(f"   文件: {issue.file_path}")
                    report.append(f"   位置: 第 {issue.line_number} 行, 第 {issue.column} 列")
                    report.append(f"   规则: {issue.rule_id}")
                    report.append(f"   描述: {issue.description}")
                    report.append(f"   代码: {issue.code_snippet}")
                    report.append(f"   建议: {issue.recommendation}")
        
        return "\n".join(report)
    
    def _generate_json_report(self, issues: List[SecurityIssue]) -> str:
        """生成JSON格式报告"""
        report_data = {
            "scan_summary": {
                "total_issues": len(issues),
                "critical": len([i for i in issues if i.severity == SeverityLevel.CRITICAL]),
                "high": len([i for i in issues if i.severity == SeverityLevel.HIGH]),
                "medium": len([i for i in issues if i.severity == SeverityLevel.MEDIUM]),
                "low": len([i for i in issues if i.severity == SeverityLevel.LOW]),
                "info": len([i for i in issues if i.severity == SeverityLevel.INFO])
            },
            "issues": []
        }
        
        for issue in issues:
            report_data["issues"].append({
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "column": issue.column,
                "rule_id": issue.rule_id,
                "severity": issue.severity.value,
                "title": issue.title,
                "description": issue.description,
                "code_snippet": issue.code_snippet,
                "recommendation": issue.recommendation
            })
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="Python安全静态分析工具")
    parser.add_argument("path", help="要扫描的文件或目录路径")
    parser.add_argument("-r", "--recursive", action="store_true", help="递归扫描子目录")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="报告格式")
    parser.add_argument("-o", "--output", help="输出文件路径")
    
    args = parser.parse_args()
    
    scanner = PythonSecurityScanner()
    
    # 扫描
    if os.path.isfile(args.path):
        issues = scanner.scan_file(args.path)
    elif os.path.isdir(args.path):
        issues = scanner.scan_directory(args.path, args.recursive)
    else:
        print(f"错误: 路径 {args.path} 不存在")
        sys.exit(1)
    
    # 生成报告
    report = scanner.generate_report(issues, args.format)
    
    # 输出报告
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"报告已保存到: {args.output}")
    else:
        print(report)
    
    # 返回适当的退出码
    critical_high_issues = [i for i in issues if i.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
    if critical_high_issues:
        sys.exit(1)  # 发现严重问题
    else:
        sys.exit(0)  # 无严重问题

if __name__ == "__main__":
    main()

