#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import random
import string
from aiohttp import web

# --- 核心环境变量 ---
UUID = os.environ.get('UUID', '7bd180e8-1142-4387-93f5-03e8d750a896')   # 节点UUID
DOMAIN = os.environ.get('DOMAIN', '')                # 域名
NAME = os.environ.get('NAME', '')                    # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])          # WS 隧道路径
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true' 
DEBUG = os.environ.get('DEBUG', '').lower() == 'true' 

# 全局变量
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

# 禁用框架高频日志
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# ==========================================
# 静态页面动态变异 (防 Shodan/FOFA 哈希聚类)
# ==========================================
def load_and_mutate_html():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html = f.read()
        
        # 随机生成 20-50 位的干扰字符串
        noise_comment = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(20, 50)))
        noise_id = ''.join(random.choices(string.ascii_letters, k=random.randint(10, 20)))
        
        # 在 </head> 前动态注入不可见的噪音，彻底改变页面的 SHA256 哈希
        mutation = f'\n\n<div style="display:none;" id="{noise_id}"></div>\n</head>'
        return html.replace('</head>', mutation)
    except:
        # 如果读取不到文件，返回一个伪装的标准 Nginx 404 页面
        return "<html>\n<head><title>404 Not Found</title></head>\n<body>\n<center><h1>404 Not Found</h1></center>\n<hr><center>nginx</center>\n</body>\n</html>"

# 缓存在内存中，避免每次请求都去读写磁盘
MUTATED_HTML = load_and_mutate_html()


def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
              for blocked in BLOCKED_DOMAINS)

async def get_isp():
    global ISP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip', headers={'User-Agent': 'Mozilla/5.0'}, timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except:
        pass
    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=5) as resp:
                    if resp.status == 200:
                        ip = await resp.text()
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except:
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except:
        pass
    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except:
            continue
    return host 

class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)
        
    async def _forward_streams(self, websocket, reader, writer):
        async def forward_ws_to_tcp():
            try:
                async for msg in websocket:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data)
                        await writer.drain()
            except:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
        
        async def forward_tcp_to_ws():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except:
                pass
        
        await asyncio.gather(forward_ws_to_tcp(), forward_tcp_to_ws())

    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 18 or first_msg[0] != 0 or first_msg[1:17] != self.uuid_bytes:
                return False
            i = first_msg[17] + 19
            if i + 3 > len(first_msg): return False
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            
            host = ''
            if atyp == 1:
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:
                host_len = first_msg[i]
                i += 1
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            await websocket.send_bytes(bytes([0, 0]))
            resolved_host = await resolve_host(host)
            
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()
                await self._forward_streams(websocket, reader, writer)
            except Exception as e:
                pass
            return True
        except:
            return False
    
    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 58: return False
            received_hash_hex = first_msg[:56].decode('ascii', errors='ignore')
            
            expected_hash_hex1 = hashlib.sha224(self.uuid.encode()).hexdigest()
            expected_hash_hex2 = hashlib.sha224(UUID.encode()).hexdigest()
            
            if received_hash_hex not in (expected_hash_hex1, expected_hash_hex2):
                return False
            
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n': offset += 2
            if first_msg[offset] != 1: return False
            offset += 1
            atyp = first_msg[offset]
            offset += 1
            
            host = ''
            if atyp == 1:
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                await self._forward_streams(websocket, reader, writer)
            except Exception as e:
                pass
            return True
        except:
            return False
    
    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 7: return False
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            
            host = ''
            if atyp == 1:
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()
                await self._forward_streams(websocket, reader, writer)
            except Exception as e:
                pass
            return True
        except:
            return False

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    
    if f'/{WSPATH}' not in request.path:
        await ws.close()
        return ws
    
    proxy = ProxyHandler(CUUID)
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        
        msg_data = first_msg.data
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await proxy.handle_vless(ws, msg_data): return ws
        if len(msg_data) >= 58:
            if await proxy.handle_trojan(ws, msg_data): return ws
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg_data): return ws
        
        await ws.close()
    except:
        await ws.close()
    
    return ws

# --- 根路径：只返回混淆后的静态 HTML ---
async def root_handler(request):
    return web.Response(text=MUTATED_HTML, content_type='text/html')

# --- 订阅路径：直接使用 UUID ---
async def sub_handler(request):
    await get_isp()
    await get_ip()
    
    name_part = f"{NAME}-{ISP}" if NAME else ISP
    tls_param = 'tls' if Tls == 'tls' else 'none'
    ss_tls_param = 'tls;' if Tls == 'tls' else ''
    
    vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
    trojan_url = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
    ss_method_password = base64.b64encode(f"none:{UUID}".encode()).decode()
    ss_url = f"ss://{ss_method_password}@{CurrentDomain}:{CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain};path%3D%2F{WSPATH};{ss_tls_param}sni%3D{CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#{name_part}"
    
    subscription = f"{vless_url}\n{trojan_url}\n{ss_url}"
    base64_content = base64.b64encode(subscription.encode()).decode()
    
    return web.Response(text=base64_content + '\n', content_type='text/plain')

async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return
    # 保活链接同步修改为使用 UUID 路径
    full_url = f"https://{DOMAIN}/{UUID}"
    try:
        await asyncio.sleep(random.uniform(1.0, 10.0))
        async with aiohttp.ClientSession() as session:
            await session.post("https://oooo.serv00.net/add-url", json={"url": full_url}, headers={'Content-Type': 'application/json'})
    except:
        pass

async def main():
    actual_port = PORT
    if not is_port_available(actual_port):
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
        else:
            sys.exit(1)
    
    app = web.Application()
    
    # --- 路由分离设计 ---
    app.router.add_get('/', root_handler)            # 访问根目录返回伪装页
    app.router.add_get(f'/{UUID}', sub_handler)      # 访问 /UUID 返回订阅节点
    app.router.add_get(f'/{WSPATH}', websocket_handler) # 访问 /WSPATH 建立代理隧道
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"Server is running on port {actual_port}")
    
    await add_access_task()
    
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass