#!/usr/bin/env python3
“””
MCP Server with Local Commands, Web Search, and Claude API Integration
“””

import asyncio
import json
import logging
import subprocess
import sys
import webbrowser
import platform
import os
from typing import Any, Dict, List, Optional
import requests
import anthropic
from mcp.server import Server
from mcp.types import (
CallToolResult,
ListToolsResult,
Tool,
TextContent,
ImageContent,
EmbeddedResource
)

# 配置日志

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(**name**)

class LocalMCPServer:
def **init**(self, claude_api_key: Optional[str] = None):
“”“初始化MCP服务器”””
self.server = Server(“local-assistant”)
self.claude_client = None

```
    if claude_api_key:
        self.claude_client = anthropic.Anthropic(api_key=claude_api_key)
    
    # 注册工具
    self._register_tools()
    
def _register_tools(self):
    """注册所有可用的工具"""
    
    @self.server.list_tools()
    async def list_tools() -> ListToolsResult:
        """列出所有可用工具"""
        return ListToolsResult(
            tools=[
                Tool(
                    name="execute_command",
                    description="执行本地系统命令",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "要执行的命令"
                            },
                            "shell": {
                                "type": "boolean",
                                "description": "是否使用shell执行",
                                "default": False
                            },
                            "timeout": {
                                "type": "number",
                                "description": "超时时间（秒）",
                                "default": 30
                            }
                        },
                        "required": ["command"]
                    }
                ),
                Tool(
                    name="open_application",
                    description="打开本地应用程序或文件",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "应用程序路径或文件路径"
                            },
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "启动参数",
                                "default": []
                            }
                        },
                        "required": ["path"]
                    }
                ),
                Tool(
                    name="open_url",
                    description="在默认浏览器中打开URL",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "要打开的URL"
                            }
                        },
                        "required": ["url"]
                    }
                ),
                Tool(
                    name="web_search",
                    description="执行网页搜索",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "搜索查询"
                            },
                            "engine": {
                                "type": "string",
                                "description": "搜索引擎",
                                "enum": ["google", "bing", "duckduckgo"],
                                "default": "google"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="get_system_info",
                    description="获取系统信息",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "info_type": {
                                "type": "string",
                                "description": "信息类型",
                                "enum": ["basic", "processes", "network", "disk"],
                                "default": "basic"
                            }
                        }
                    }
                ),
                Tool(
                    name="file_operations",
                    description="文件操作（读取、写入、列表）",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "操作类型",
                                "enum": ["read", "write", "list", "exists", "delete"]
                            },
                            "path": {
                                "type": "string",
                                "description": "文件或目录路径"
                            },
                            "content": {
                                "type": "string",
                                "description": "写入的内容（仅用于write操作）"
                            }
                        },
                        "required": ["operation", "path"]
                    }
                ),
                Tool(
                    name="claude_chat",
                    description="与Claude AI聊天",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "发送给Claude的消息"
                            },
                            "model": {
                                "type": "string",
                                "description": "使用的Claude模型",
                                "default": "claude-3-sonnet-20240229"
                            },
                            "max_tokens": {
                                "type": "number",
                                "description": "最大token数",
                                "default": 1000
                            }
                        },
                        "required": ["message"]
                    }
                )
            ]
        )

    @self.server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
        """调用工具"""
        try:
            if name == "execute_command":
                return await self._execute_command(**arguments)
            elif name == "open_application":
                return await self._open_application(**arguments)
            elif name == "open_url":
                return await self._open_url(**arguments)
            elif name == "web_search":
                return await self._web_search(**arguments)
            elif name == "get_system_info":
                return await self._get_system_info(**arguments)
            elif name == "file_operations":
                return await self._file_operations(**arguments)
            elif name == "claude_chat":
                return await self._claude_chat(**arguments)
            else:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"未知工具: {name}")]
                )
        except Exception as e:
            logger.error(f"工具调用错误 {name}: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"错误: {str(e)}")]
            )

async def _execute_command(self, command: str, shell: bool = False, timeout: int = 30) -> CallToolResult:
    """执行系统命令"""
    try:
        if shell:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        else:
            cmd_parts = command.split()
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), 
            timeout=timeout
        )
        
        result = {
            "returncode": process.returncode,
            "stdout": stdout.decode('utf-8', errors='ignore'),
            "stderr": stderr.decode('utf-8', errors='ignore')
        }
        
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
        )
    except asyncio.TimeoutError:
        return CallToolResult(
            content=[TextContent(type="text", text="命令执行超时")]
        )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"命令执行失败: {str(e)}")]
        )

async def _open_application(self, path: str, args: List[str] = None) -> CallToolResult:
    """打开应用程序"""
    try:
        if args is None:
            args = []
        
        system = platform.system()
        
        if system == "Windows":
            subprocess.Popen([path] + args, shell=True)
        elif system == "Darwin":  # macOS
            subprocess.Popen(["open", path] + args)
        else:  # Linux
            subprocess.Popen([path] + args)
        
        return CallToolResult(
            content=[TextContent(type="text", text=f"已打开应用程序: {path}")]
        )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"打开应用程序失败: {str(e)}")]
        )

async def _open_url(self, url: str) -> CallToolResult:
    """在浏览器中打开URL"""
    try:
        webbrowser.open(url)
        return CallToolResult(
            content=[TextContent(type="text", text=f"已在浏览器中打开: {url}")]
        )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"打开URL失败: {str(e)}")]
        )

async def _web_search(self, query: str, engine: str = "google") -> CallToolResult:
    """执行网页搜索"""
    try:
        search_urls = {
            "google": f"https://www.google.com/search?q={query}",
            "bing": f"https://www.bing.com/search?q={query}",
            "duckduckgo": f"https://duckduckgo.com/?q={query}"
        }
        
        url = search_urls.get(engine, search_urls["google"])
        webbrowser.open(url)
        
        return CallToolResult(
            content=[TextContent(type="text", text=f"已在{engine}中搜索: {query}")]
        )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"搜索失败: {str(e)}")]
        )

async def _get_system_info(self, info_type: str = "basic") -> CallToolResult:
    """获取系统信息"""
    try:
        info = {}
        
        if info_type == "basic":
            info = {
                "platform": platform.platform(),
                "system": platform.system(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "machine": platform.machine(),
                "node": platform.node()
            }
        elif info_type == "processes":
            try:
                import psutil
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    processes.append(proc.info)
                info["processes"] = processes[:10]  # 只显示前10个进程
            except ImportError:
                info["error"] = "需要安装psutil库来获取进程信息"
        elif info_type == "network":
            try:
                import psutil
                info["network"] = psutil.net_io_counters()._asdict()
            except ImportError:
                info["error"] = "需要安装psutil库来获取网络信息"
        elif info_type == "disk":
            try:
                import psutil
                disk_usage = psutil.disk_usage('/')
                info["disk"] = {
                    "total": disk_usage.total,
                    "used": disk_usage.used,
                    "free": disk_usage.free,
                    "percentage": (disk_usage.used / disk_usage.total) * 100
                }
            except ImportError:
                info["error"] = "需要安装psutil库来获取磁盘信息"
        
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(info, ensure_ascii=False, indent=2))]
        )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"获取系统信息失败: {str(e)}")]
        )

async def _file_operations(self, operation: str, path: str, content: str = None) -> CallToolResult:
    """文件操作"""
    try:
        if operation == "read":
            with open(path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            return CallToolResult(
                content=[TextContent(type="text", text=file_content)]
            )
        elif operation == "write":
            if content is None:
                raise ValueError("写入操作需要提供内容")
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return CallToolResult(
                content=[TextContent(type="text", text=f"已写入文件: {path}")]
            )
        elif operation == "list":
            items = os.listdir(path)
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(items, ensure_ascii=False, indent=2))]
            )
        elif operation == "exists":
            exists = os.path.exists(path)
            return CallToolResult(
                content=[TextContent(type="text", text=f"文件/目录存在: {exists}")]
            )
        elif operation == "delete":
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                os.rmdir(path)
            return CallToolResult(
                content=[TextContent(type="text", text=f"已删除: {path}")]
            )
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"不支持的操作: {operation}")]
            )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"文件操作失败: {str(e)}")]
        )

async def _claude_chat(self, message: str, model: str = "claude-3-sonnet-20240229", max_tokens: int = 1000) -> CallToolResult:
    """与Claude AI聊天"""
    if not self.claude_client:
        return CallToolResult(
            content=[TextContent(type="text", text="Claude API客户端未初始化，请提供API密钥")]
        )
    
    try:
        response = self.claude_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": message}]
        )
        
        return CallToolResult(
            content=[TextContent(type="text", text=response.content[0].text)]
        )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Claude API调用失败: {str(e)}")]
        )

async def run(self, transport):
    """运行服务器"""
    async with self.server.run(transport):
        await asyncio.Event().wait()
```

async def main():
“”“主函数”””
# 从环境变量获取Claude API密钥
claude_api_key = os.getenv(“ANTHROPIC_API_KEY”)

```
if not claude_api_key:
    logger.warning("未找到ANTHROPIC_API_KEY环境变量，Claude聊天功能将不可用")

# 创建MCP服务器
server = LocalMCPServer(claude_api_key)

# 使用stdio传输
from mcp.server.stdio import stdio_server

logger.info("启动MCP服务器...")
await server.run(stdio_server())
```

if **name** == “**main**”:
try:
asyncio.run(main())
except KeyboardInterrupt:
logger.info(“服务器已停止”)
except Exception as e:
logger.error(f”服务器错误: {e}”)
sys.exit(1)