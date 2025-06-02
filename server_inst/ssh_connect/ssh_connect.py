from typing import Any, Dict, Optional
import paramiko
import chardet
from mcp.server.fastmcp import FastMCP
import json
import time

# Initialize FastMCP server
mcp = FastMCP("ssh-connector")

# Global connection pool to reuse connections
_connections: Dict[str, paramiko.SSHClient] = {}

class SSHConnectionManager:
    """管理SSH连接的类"""
    
    @staticmethod
    def _get_connection_key(hostname: str, username: str, port: int = 22) -> str:
        """生成连接的唯一标识"""
        return f"{username}@{hostname}:{port}"
    
    @staticmethod
    def _decode_bytes(byte_data: bytes) -> str:
        """智能解码字节数据"""
        if not byte_data:
            return ""
        
        # 尝试常见编码
        encodings = ['utf-8', 'gbk', 'gb2312', 'cp936', 'latin1', 'cp1252']
        for encoding in encodings:
            try:
                return byte_data.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # 使用chardet检测编码
        try:
            detected = chardet.detect(byte_data)
            if detected['encoding']:
                return byte_data.decode(detected['encoding'])
        except:
            pass
        
        # 最后使用replace模式
        return byte_data.decode('utf-8', errors='replace')
    
    @classmethod
    async def get_connection(cls, hostname: str, username: str, password: str = None, 
                           key_path: str = None, port: int = 22) -> Optional[paramiko.SSHClient]:
        """获取或创建SSH连接"""
        conn_key = cls._get_connection_key(hostname, username, port)
        
        # 检查是否已有连接
        if conn_key in _connections:
            client = _connections[conn_key]
            try:
                # 测试连接是否还活着
                client.exec_command("echo test", timeout=5)
                return client
            except:
                # 连接已断开，移除并重新创建
                try:
                    client.close()
                except:
                    pass
                del _connections[conn_key]
        
        # 创建新连接
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if key_path:
                key = paramiko.RSAKey.from_private_key_file(key_path)
                client.connect(hostname, port=port, username=username, pkey=key, timeout=10)
            else:
                client.connect(hostname, port=port, username=username, password=password, timeout=10)
            
            _connections[conn_key] = client
            return client
        except Exception as e:
            try:
                client.close()
            except:
                pass
            raise e
    
    @classmethod
    async def execute_command(cls, client: paramiko.SSHClient, command: str, timeout: int = 30) -> Dict[str, Any]:
        """执行SSH命令"""
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            
            # 等待命令执行完成
            exit_status = stdout.channel.recv_exit_status()
            
            # 读取输出
            stdout_bytes = stdout.read()
            stderr_bytes = stderr.read()
            
            # 解码输出
            output = cls._decode_bytes(stdout_bytes)
            error = cls._decode_bytes(stderr_bytes)
            
            return {
                'stdout': output.strip(),
                'stderr': error.strip(),
                'exit_status': exit_status,
                'success': exit_status == 0
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_status': -1,
                'success': False
            }

@mcp.tool()
async def ssh_connect(hostname: str, username: str, password: str = None, 
                     key_path: str = None, port: int = 22) -> str:
    """建立SSH连接到远程主机
    
    Args:
        hostname: 远程主机IP地址或域名
        username: SSH用户名
        password: SSH密码 (可选，如果使用密钥认证)
        key_path: SSH私钥文件路径 (可选)
        port: SSH端口号 (默认22)
    """
    try:
        client = await SSHConnectionManager.get_connection(
            hostname=hostname,
            username=username, 
            password=password,
            key_path=key_path,
            port=port
        )
        
        if client:
            # 获取基本系统信息
            result = await SSHConnectionManager.execute_command(client, "uname -a || ver")
            if result['success']:
                system_info = result['stdout']
            else:
                system_info = "无法获取系统信息"
            
            return f"成功连接到 {hostname}:{port}\n系统信息: {system_info}"
        else:
            return f"连接到 {hostname}:{port} 失败"
            
    except Exception as e:
        return f"连接失败: {str(e)}"

@mcp.tool()
async def ssh_execute(hostname: str, username: str, command: str, 
                     password: str = None, key_path: str = None, 
                     port: int = 22, timeout: int = 30) -> str:
    """在远程主机上执行命令
    
    Args:
        hostname: 远程主机IP地址或域名
        username: SSH用户名
        command: 要执行的命令
        password: SSH密码 (可选)
        key_path: SSH私钥文件路径 (可选)
        port: SSH端口号 (默认22)
        timeout: 命令执行超时时间(秒，默认30)
    """
    try:
        client = await SSHConnectionManager.get_connection(
            hostname=hostname,
            username=username,
            password=password,
            key_path=key_path,
            port=port
        )
        
        result = await SSHConnectionManager.execute_command(client, command, timeout)
        
        if result['success']:
            output = result['stdout']
            if result['stderr']:
                output += f"\n[警告]: {result['stderr']}"
            return output or "命令执行成功，无输出"
        else:
            return f"命令执行失败 (退出码: {result['exit_status']})\n错误: {result['stderr']}"
            
    except Exception as e:
        return f"执行命令失败: {str(e)}"

@mcp.tool()
async def ssh_get_system_info(hostname: str, username: str, password: str = None, 
                             key_path: str = None, port: int = 22) -> str:
    """获取远程主机的详细系统信息
    
    Args:
        hostname: 远程主机IP地址或域名
        username: SSH用户名
        password: SSH密码 (可选)
        key_path: SSH私钥文件路径 (可选)
        port: SSH端口号 (默认22)
    """
    try:
        client = await SSHConnectionManager.get_connection(
            hostname=hostname,
            username=username,
            password=password,
            key_path=key_path,
            port=port
        )
        
        # 定义要执行的系统信息命令
        commands = {
            'system': 'uname -a 2>/dev/null || systeminfo | findstr /C:"OS Name" /C:"OS Version" 2>/dev/null',
            'hostname': 'hostname',
            'uptime': 'uptime 2>/dev/null || net statistics server | findstr "since" 2>/dev/null',
            'memory': 'free -h 2>/dev/null || wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /format:list 2>/dev/null',
            'disk': 'df -h 2>/dev/null || wmic logicaldisk get size,freespace,caption /format:list 2>/dev/null',
            'cpu': 'lscpu | grep "Model name" 2>/dev/null || wmic cpu get name /format:list 2>/dev/null',
            'processes': 'ps aux | head -10 2>/dev/null || tasklist | findstr /V "Image Name" | head -10 2>/dev/null'
        }
        
        info_parts = []
        for category, command in commands.items():
            result = await SSHConnectionManager.execute_command(client, command, timeout=15)
            if result['success'] and result['stdout']:
                info_parts.append(f"=== {category.upper()} ===")
                info_parts.append(result['stdout'])
                info_parts.append("")
            elif result['stderr']:
                info_parts.append(f"=== {category.upper()} ===")
                info_parts.append(f"获取失败: {result['stderr']}")
                info_parts.append("")
        
        return "\n".join(info_parts) if info_parts else "无法获取系统信息"
        
    except Exception as e:
        return f"获取系统信息失败: {str(e)}"

@mcp.tool()
async def ssh_file_operations(hostname: str, username: str, operation: str, 
                             path: str, password: str = None, key_path: str = None, 
                             port: int = 22, content: str = None) -> str:
    """在远程主机上进行文件操作
    
    Args:
        hostname: 远程主机IP地址或域名
        username: SSH用户名
        operation: 操作类型 (list, read, write, delete, mkdir)
        path: 文件或目录路径
        password: SSH密码 (可选)
        key_path: SSH私钥文件路径 (可选)
        port: SSH端口号 (默认22)
        content: 写入文件的内容 (仅当operation为write时需要)
    """
    try:
        client = await SSHConnectionManager.get_connection(
            hostname=hostname,
            username=username,
            password=password,
            key_path=key_path,
            port=port
        )
        
        if operation == "list":
            command = f'ls -la "{path}" 2>/dev/null || dir "{path}" 2>/dev/null'
        elif operation == "read":
            command = f'cat "{path}" 2>/dev/null || type "{path}" 2>/dev/null'
        elif operation == "write":
            if content is None:
                return "写入操作需要提供content参数"
            # 转义特殊字符
            escaped_content = content.replace('"', '\\"').replace('`', '\\`').replace('$', '\\$')
            command = f'echo "{escaped_content}" > "{path}" 2>/dev/null || echo {escaped_content} > "{path}" 2>/dev/null'
        elif operation == "delete":
            command = f'rm -f "{path}" 2>/dev/null || del "{path}" 2>/dev/null'
        elif operation == "mkdir":
            command = f'mkdir -p "{path}" 2>/dev/null || mkdir "{path}" 2>/dev/null'
        else:
            return f"不支持的操作: {operation}。支持的操作: list, read, write, delete, mkdir"
        
        result = await SSHConnectionManager.execute_command(client, command, timeout=30)
        
        if result['success']:
            return result['stdout'] or f"{operation} 操作完成"
        else:
            return f"{operation} 操作失败: {result['stderr']}"
            
    except Exception as e:
        return f"文件操作失败: {str(e)}"

@mcp.tool()
async def ssh_disconnect(hostname: str, username: str, port: int = 22) -> str:
    """断开SSH连接
    
    Args:
        hostname: 远程主机IP地址或域名
        username: SSH用户名
        port: SSH端口号 (默认22)
    """
    conn_key = SSHConnectionManager._get_connection_key(hostname, username, port)
    
    if conn_key in _connections:
        try:
            _connections[conn_key].close()
            del _connections[conn_key]
            return f"已断开与 {hostname}:{port} 的连接"
        except Exception as e:
            return f"断开连接时出错: {str(e)}"
    else:
        return f"没有找到与 {hostname}:{port} 的活跃连接"

@mcp.tool()
async def ssh_list_connections() -> str:
    """列出所有活跃的SSH连接"""
    if not _connections:
        return "当前没有活跃的SSH连接"
    
    active_connections = []
    to_remove = []
    
    for conn_key, client in _connections.items():
        try:
            # 测试连接是否还活着
            client.exec_command("echo test", timeout=5)
            active_connections.append(conn_key)
        except:
            to_remove.append(conn_key)
    
    # 清理断开的连接
    for conn_key in to_remove:
        try:
            _connections[conn_key].close()
        except:
            pass
        del _connections[conn_key]
    
    if active_connections:
        return "活跃的SSH连接:\n" + "\n".join(f"- {conn}" for conn in active_connections)
    else:
        return "当前没有活跃的SSH连接"

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')