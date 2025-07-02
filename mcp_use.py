#!/usr/bin/env python3
“””
MCP本地助手服务器使用示例
“””

import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def test_mcp_server():
“”“测试MCP服务器功能”””

```
# 连接到MCP服务器
server_params = StdioServerParameters(
    command="python",
    args=["mcp_server.py"]
)

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        
        # 初始化连接
        await session.initialize()
        
        print("🚀 MCP本地助手服务器测试")
        print("=" * 50)
        
        # 1. 获取可用工具列表
        print("\n📋 获取工具列表...")
        tools = await session.list_tools()
        print(f"可用工具数量: {len(tools.tools)}")
        for tool in tools.tools:
            print(f"  - {tool.name}: {tool.description}")
        
        # 2. 测试系统信息获取
        print("\n💻 获取系统信息...")
        result = await session.call_tool("get_system_info", {"info_type": "basic"})
        if result.content:
            system_info = json.loads(result.content[0].text)
            print(f"操作系统: {system_info.get('system')}")
            print(f"平台: {system_info.get('platform')}")
            print(f"处理器: {system_info.get('processor')}")
        
        # 3. 测试命令执行
        print("\n⚡ 执行命令测试...")
        commands = [
            {"command": "echo Hello MCP!", "shell": True},
            {"command": "python --version", "shell": True},
            {"command": "pwd" if system_info.get('system') != 'Windows' else "cd", "shell": True}
        ]
        
        for cmd_info in commands:
            print(f"执行: {cmd_info['command']}")
            result = await session.call_tool("execute_command", cmd_info)
            if result.content:
                output = json.loads(result.content[0].text)
                if output.get('returncode') == 0:
                    print(f"✅ 输出: {output.get('stdout', '').strip()}")
                else:
                    print(f"❌ 错误: {output.get('stderr', '').strip()}")
        
        # 4. 测试文件操作
        print("\n📁 文件操作测试...")
        test_file = "test_mcp.txt"
        test_content = "这是MCP服务器的测试文件\n当前时间: " + str(asyncio.get_event_loop().time())
        
        # 写入文件
        result = await session.call_tool("file_operations", {
            "operation": "write",
            "path": test_file,
            "content": test_content
        })
        print(f"写入文件: {result.content[0].text}")
        
        # 读取文件
        result = await session.call_tool("file_operations", {
            "operation": "read",
            "path": test_file
        })
        print(f"读取文件内容: {result.content[0].text[:50]}...")
        
        # 删除文件
        result = await session.call_tool("file_operations", {
            "operation": "delete",
            "path": test_file
        })
        print(f"删除文件: {result.content[0].text}")
        
        # 5. 测试网页搜索
        print("\n🔍 网页搜索测试...")
        result = await session.call_tool("web_search", {
```