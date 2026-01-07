import sys
import random
import threading
import time
import ipaddress
import asyncio
import aiohttp
import socket
import ssl
from datetime import datetime
from typing import List, Optional, Dict
import os

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QLineEdit, QProgressBar, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QGridLayout, QHeaderView,
    QTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QClipboard, QIcon

BTN_W = 120
BTN_H = 38
SPACING = 8

FONT_BTN = QFont("Microsoft YaHei", 12)
FONT_TITLE = QFont("Microsoft YaHei", 28)
FONT_STATUS = QFont("Microsoft YaHei", 9)

CF_IPV4_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
    "172.64.0.0/17", "172.64.128.0/18", "172.64.192.0/19", "172.64.224.0/22",
    "172.64.229.0/24", "172.64.230.0/23", "172.64.232.0/21", "172.64.240.0/21",
    "172.64.248.0/21", "172.65.0.0/16", "172.66.0.0/16", "172.67.0.0/16",
    "131.0.72.0/22"
]

AIRPORT_CODES = {
    "HKG": "香港", "TPE": "台北", "KHH": "高雄", "MFM": "澳门",
    "NRT": "东京", "HND": "东京", "KIX": "大阪", "NGO": "名古屋",
    "FUK": "福冈", "CTS": "札幌", "OKA": "冲绳",
    "ICN": "首尔", "GMP": "首尔", "PUS": "釜山",
    "SIN": "新加坡", "BKK": "曼谷", "DMK": "曼谷",
    "KUL": "吉隆坡", "HKT": "普吉岛",
    "MNL": "马尼拉", "CEB": "宿务",
    "HAN": "河内", "SGN": "胡志明市",
    "JKT": "雅加达", "DPS": "巴厘岛",
    "DEL": "德里", "BOM": "孟买", "MAA": "金奈",
    "DXB": "迪拜", "AUH": "阿布扎比",
    "SJC": "圣何塞", "LAX": "洛杉矶", "SFO": "旧金山",
    "SEA": "西雅图", "PDX": "波特兰",
    "LAS": "拉斯维加斯", "PHX": "菲尼克斯",
    "DEN": "丹佛", "DFW": "达拉斯", "IAH": "休斯顿",
    "ORD": "芝加哥", "MSP": "明尼阿波利斯",
    "ATL": "亚特兰大", "MIA": "迈阿密", "MCO": "奥兰多",
    "JFK": "纽约", "EWR": "纽约", "LGA": "纽约",
    "BOS": "波士顿", "PHL": "费城", "IAD": "华盛顿",
    "YYZ": "多伦多", "YVR": "温哥华", "YUL": "蒙特利尔",
    "LHR": "伦敦", "LGW": "伦敦", "STN": "伦敦",
    "CDG": "巴黎", "ORY": "巴黎",
    "FRA": "法兰克福", "MUC": "慕尼黑", "TXL": "柏林",
    "AMS": "阿姆斯特丹", "EIN": "埃因霍温",
    "MAD": "马德里", "BCN": "巴塞罗那",
    "FCO": "罗马", "MXP": "米兰", "LIN": "米兰",
    "ZRH": "苏黎世", "GVA": "日内瓦",
    "VIE": "维也纳", "PRG": "布拉格",
    "WAW": "华沙", "KRK": "克拉科夫",
    "HEL": "赫尔辛基", "OSL": "奥斯陆", "ARN": "斯德哥尔摩",
    "CPH": "哥本哈根",
    "SYD": "悉尼", "MEL": "墨尔本", "BNE": "布里斯班",
    "PER": "珀斯", "ADL": "阿德莱德",
    "AKL": "奥克兰", "WLG": "惠灵顿",
    "GRU": "圣保罗", "GIG": "里约热内卢", "EZE": "布宜诺斯艾利斯",
    "SCL": "圣地亚哥", "LIM": "利马", "BOG": "波哥大",
    "JNB": "约翰内斯堡", "CPT": "开普敦", "CAI": "开罗",
}


class AsyncScanner:
    
    def __init__(self, log_callback=None, progress_callback=None, result_callback=None):
        self.max_workers = 150
        self.timeout = 3
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.running = True
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        
    def generate_ips_from_cidrs(self) -> List[str]:
        ip_list = []
        for cidr in CF_IPV4_CIDRS:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                
                for subnet in network.subnets(new_prefix=24):
                    if subnet.num_addresses > 2:
                        hosts = list(subnet.hosts())
                        if hosts:
                            random_ip = str(random.choice(hosts))
                            ip_list.append(random_ip)
                            
            except ValueError as e:
                if self.log_callback:
                    self.log_callback(f"处理CIDR {cidr} 时出错: {e}")
                continue
        
        return ip_list
    
    async def test_ip_latency(self, session: aiohttp.ClientSession, ip: str) -> Optional[float]:
        if not self.running:
            return None
            
        start_time = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443),
                timeout=self.timeout
            )
            latency = (time.monotonic() - start_time) * 1000
            writer.close()
            await writer.wait_closed()
            return round(latency, 2)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ConnectionError):
            return None
        except Exception:
            return None
    
    async def get_iata_code(self, session: aiohttp.ClientSession, ip: str) -> Optional[str]:
        if not self.running:
            return None
            
        test_configs = [
            ("http", "/cdn-cgi/trace", {"User-Agent": "curl/7.68.0"}),
            ("https", "/cdn-cgi/trace", {"User-Agent": "curl/7.68.0"}),
        ]
        
        for protocol, path, headers in test_configs:
            url = f"{protocol}://{ip}{path}"
            
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    headers=headers,
                    allow_redirects=False
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        
                        for line in text.strip().split('\n'):
                            if line.startswith('colo='):
                                colo_value = line.split('=', 1)[1].strip()
                                if colo_value and colo_value.upper() != 'UNKNOWN':
                                    return colo_value.upper()
                        
                        if 'CF-RAY' in response.headers:
                            cf_ray = response.headers['CF-RAY']
                            if '-' in cf_ray:
                                parts = cf_ray.split('-')
                                for part in parts[-2:]:
                                    if len(part) == 3 and part.isalpha():
                                        return part.upper()
                                
            except Exception:
                continue
        
        return None
    
    def get_iata_translation(self, iata_code: str) -> str:
        if iata_code in AIRPORT_CODES:
            return AIRPORT_CODES[iata_code]
        return iata_code
    
    async def test_single_ip(self, session: aiohttp.ClientSession, ip: str):
        if not self.running:
            return None
        
        latency = await self.test_ip_latency(session, ip)
        
        if latency is not None and latency < 5000:
            if self.running:
                try:
                    iata_code = await self.get_iata_code(session, ip)
                except Exception:
                    iata_code = None
                    
            return {
                'ip': ip,
                'latency': latency,
                'iata_code': iata_code,
                'chinese_name': self.get_iata_translation(iata_code) if iata_code else "未知地区",
                'success': True,
                'scan_time': datetime.now().strftime("%H:%M:%S")
            }
        else:
            return None
    
    async def batch_test_ips(self, ip_list: List[str]):
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def test_with_semaphore(session: aiohttp.ClientSession, ip: str):
            async with semaphore:
                return await self.test_single_ip(session, ip)
        
        connector = aiohttp.TCPConnector(
            limit=self.max_workers,
            force_close=True,
            enable_cleanup_closed=True,
            limit_per_host=0
        )
        
        successful_results = []
        start_time = time.time()
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for ip in ip_list:
                if not self.running:
                    break
                task = asyncio.create_task(test_with_semaphore(session, ip))
                tasks.append(task)
            
            completed = 0
            total = len(tasks)
            
            last_update_time = time.time()
            update_interval = 0.5
            
            for future in asyncio.as_completed(tasks):
                if not self.running:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    break
                
                result = await future
                completed += 1
                
                if result:
                    successful_results.append(result)
                
                current_time = time.time()
                if current_time - last_update_time >= update_interval or completed == total:
                    elapsed = current_time - start_time
                    ips_per_second = completed / elapsed if elapsed > 0 else 0
                    remaining = total - completed
                    eta = remaining / ips_per_second if ips_per_second > 0 else 0
                    
                    if self.progress_callback:
                        self.progress_callback(completed, total, len(successful_results), ips_per_second, eta)
                    
                    last_update_time = current_time
        
        return successful_results
    
    async def run_scan_async(self):
        try:
            ip_list = self.generate_ips_from_cidrs()
            
            if not ip_list:
                if self.log_callback:
                    self.log_callback("错误: 未能生成IP列表")
                return None
            
            if self.log_callback:
                self.log_callback(f"扫描阶段：开始测试 {len(ip_list)} 个IP的延迟和地区码...")
            
            results = await self.batch_test_ips(ip_list)
            
            if not self.running:
                if self.log_callback:
                    self.log_callback("扫描被用户中止")
                return None
            
            return results
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"扫描过程中出现错误: {str(e)}")
            return None
    
    def stop(self):
        self.running = False


class SpeedTestWorker(QThread):
    progress_update = Signal(int, int, float)
    status_message = Signal(str)
    speed_test_completed = Signal(list)
    
    def __init__(self, results: List[Dict], region_code: str = None):
        super().__init__()
        self.results = results
        self.region_code = region_code.upper() if region_code else None
        self.download_interval = 3
        self.download_time_limit = 3
        self.test_host = "speed.cloudflare.com"
        self.running = True
    
    def download_speed(self, ip: str) -> float:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = (
            "GET /__down?bytes=50000000 HTTP/1.1\r\n"
            f"Host: {self.test_host}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

        try:
            sock = socket.create_connection((ip, 443), timeout=3)
            ss = ctx.wrap_socket(sock, server_hostname=self.test_host)
            ss.sendall(req)

            start = time.time()
            data = b""
            header_done = False
            body = 0

            while time.time() - start < self.download_time_limit:
                buf = ss.recv(8192)
                if not buf:
                    break
                if not header_done:
                    data += buf
                    if b"\r\n\r\n" in data:
                        header_done = True
                        body += len(data.split(b"\r\n\r\n", 1)[1])
                else:
                    body += len(buf)

            ss.close()
            dur = time.time() - start
            return round((body / 1024 / 1024) / max(dur, 0.1), 2)

        except Exception as e:
            self.status_message.emit(f"测速失败 {ip}: {str(e)}")
            return 0.0
    
    def get_colo(self, ip: str) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = socket.create_connection((ip, 443), timeout=3)
            ss = ctx.wrap_socket(s, server_hostname=self.test_host)
            ss.sendall(
                f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {self.test_host}\r\n\r\n".encode()
            )
            data = ss.recv(2048).decode(errors="ignore")
            ss.close()
            for line in data.splitlines():
                if line.startswith("colo="):
                    return line.split("=")[1].strip()
        except:
            pass
        return None
    
    def run(self):
        try:
            if not self.results:
                self.status_message.emit("错误：没有可用的IP进行测速")
                self.speed_test_completed.emit([])
                return
            
            if self.region_code:
                filtered_results = [r for r in self.results if r.get('iata_code') and r['iata_code'].upper() == self.region_code]
                self.status_message.emit(f"找到 {len(filtered_results)} 个 {self.region_code} 地区的IP")
            else:
                filtered_results = self.results
            
            if not filtered_results:
                self.status_message.emit(f"没有找到可用的IP进行测速")
                self.speed_test_completed.emit([])
                return
            
            filtered_results.sort(key=lambda x: x.get('latency', float('inf')))
            target_ips = filtered_results[:min(5, len(filtered_results))]
            
            speed_results = []
            
            for i, ip_info in enumerate(target_ips):
                if not self.running:
                    break
                
                ip = ip_info['ip']
                latency = ip_info.get('latency', 0)
                
                self.status_message.emit(f"[{i+1}/{len(target_ips)}] 正在测速 {ip} (延迟: {latency}ms)")
                self.progress_update.emit(i+1, len(target_ips), 0)
                
                download_speed = self.download_speed(ip)
                
                colo = self.get_colo(ip)
                if colo == "Unknown" or not colo:
                    self.status_message.emit(f"IP {ip} 地区码未知，跳过")
                    continue
                
                speed_result = {
                    'ip': ip,
                    'latency': latency,
                    'download_speed': download_speed,
                    'iata_code': colo.upper(),
                    'chinese_name': AIRPORT_CODES.get(colo.upper(), '未知地区'),
                    'test_type': "地区测速" if self.region_code else "完全测速"
                }
                
                speed_results.append(speed_result)
                
                self.status_message.emit(f"  测速结果: {download_speed} MB/s, 地区码: {colo}")
                
                if i < len(target_ips) - 1:
                    for _ in range(self.download_interval * 10):
                        if not self.running:
                            break
                        time.sleep(0.1)
            
            speed_results.sort(key=lambda x: x['download_speed'], reverse=True)
            
            if speed_results:
                self.status_message.emit(f"测速完成！成功测速 {len(speed_results)}/{len(target_ips)} 个IP")
            
            self.speed_test_completed.emit(speed_results)
            
        except Exception as e:
            self.status_message.emit(f"测速过程中出现错误: {str(e)}")
            self.speed_test_completed.emit([])
    
    def stop(self):
        self.running = False


class ScanWorker(QThread):
    progress_update = Signal(int, int, int, float, float)
    status_message = Signal(str)
    scan_completed = Signal(list)
    
    def __init__(self):
        super().__init__()
        self.scanner = None
        
    def run(self):
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        self.scanner = AsyncScanner(
            log_callback=lambda msg: self.status_message.emit(msg),
            progress_callback=lambda c, t, s, sp, e: self.progress_update.emit(c, t, s, sp, e),
            result_callback=None
        )
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(self.scanner.run_scan_async())
            if results is not None:
                self.scan_completed.emit(results)
        finally:
            loop.close()
    
    def stop(self):
        if self.scanner:
            self.scanner.stop()


class CloudflareScanUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CloudFlare Scan -- 小琳解说")
        
        self.resize(430, 700)
        self.setMinimumSize(400, 600)
        
        self.setStyleSheet("background:#F9FAFB;")
        
        self.set_window_icon()
        
        self.scan_worker = None
        self.speed_test_worker = None
        self.scanning = False
        self.speed_testing = False
        self.scan_results = []
        
        self.init_ui()
    
    def set_window_icon(self):
        icon_paths = [
            "cfs.ico",
            os.path.join(os.path.dirname(__file__), "cfs.ico"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfs.ico"),
        ]
        
        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                try:
                    self.setWindowIcon(QIcon(icon_path))
                    return
                except Exception:
                    continue
        
        try:
            icon_path = os.path.join(sys._MEIPASS, "cfs.ico") if hasattr(sys, '_MEIPASS') else "cfs.ico"
            self.setWindowIcon(QIcon(icon_path))
        except Exception:
            pass
    
    def make_btn(self, text, color, text_color="white", enabled=True):
        btn = QPushButton(text)
        btn.setFixedSize(BTN_W, BTN_H)
        btn.setFont(FONT_BTN)
        btn.setEnabled(enabled)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background:{color};
                color:{text_color};
                border-radius:6px;
            }}
            QPushButton:disabled {{
                background:#E5E7EB;
                color:#6B7280;
            }}
            QPushButton:hover {{
                opacity:0.9;
            }}
        """)
        return btn
    
    def make_stop_btn(self, text, enabled=True):
        btn = QPushButton(text)
        btn.setFixedSize(BTN_W, BTN_H)
        btn.setFont(FONT_BTN)
        btn.setEnabled(enabled)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background:#EF4444;
                color:white;
                border-radius:6px;
            }}
            QPushButton:disabled {{
                background:#E5E7EB;
                color:#6B7280;
            }}
            QPushButton:hover {{
                background:#DC2626;
            }}
        """)
        return btn
    
    def make_label_btn(self, text):
        btn = QPushButton(text)
        btn.setFixedSize(BTN_W, BTN_H)
        btn.setFont(FONT_BTN)
        btn.setEnabled(False)
        btn.setCursor(Qt.ArrowCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background:#8B5CF6;
                color:white;
                border-radius:6px;
                border:1px solid #7C3AED;
            }}
        """)
        return btn
    
    def init_ui(self):
        main = QVBoxLayout(self)
        main.setContentsMargins(14, 14, 14, 14)
        main.setSpacing(14)

        title = QLabel(
            '<span style="color:#ff7a18; font-size: 32px; font-weight: bold;">CloudFlare</span> '
            '<span style="color:#000000; font-size: 32px; font-weight: bold;"> Scan</span>'
        )
        title.setAlignment(Qt.AlignCenter)
        main.addWidget(title)

        control = QGridLayout()
        control.setVerticalSpacing(10)

        row1 = QHBoxLayout()
        row1.setSpacing(SPACING)

        self.btn_ipv4 = self.make_btn("开始扫描", "#3B82F6")
        self.btn_ipv4.clicked.connect(self.start_ipv4_scan)
        
        self.btn_region = self.make_label_btn("输入地区码")

        self.input_region = QLineEdit()
        self.input_region.setFixedSize(BTN_W, BTN_H)
        self.input_region.setFont(FONT_BTN)
        self.input_region.setPlaceholderText("如：SJC, SIN")
        self.input_region.setStyleSheet("""
            QLineEdit {
                background:white;
                border:1px solid #D1D5DB;
                border-radius:6px;
                padding-left:8px;
                color:#111827;
            }
            QLineEdit:focus {
                border-color:#8B5CF6;
            }
            QLineEdit::placeholder {
                color:#9CA3AF;
            }
        """)
        self.input_region.textChanged.connect(self.region_text_changed)

        for w in (self.btn_ipv4, self.btn_region, self.input_region):
            row1.addWidget(w)

        row2 = QHBoxLayout()
        row2.setSpacing(SPACING)

        self.btn_stop = self.make_stop_btn("停止任务", enabled=False)
        self.btn_stop.clicked.connect(self.stop_all_tasks)

        self.btn_full = self.make_btn("完全测速", "#F97316", enabled=False)
        self.btn_full.clicked.connect(self.start_full_speed_test)
        
        self.btn_area = self.make_btn("地区测速", "#EC4899", enabled=False)
        self.btn_area.clicked.connect(self.start_region_speed_test)

        row2.addWidget(self.btn_stop)
        row2.addWidget(self.btn_full)
        row2.addWidget(self.btn_area)

        control.addLayout(row1, 0, 0)
        control.addLayout(row2, 1, 0)

        main.addLayout(control)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(10)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background:#E5E7EB;
                border-radius:5px;
            }
            QProgressBar::chunk {
                background:#22C55E;
                border-radius:5px;
            }
        """)
        main.addWidget(self.progress_bar)

        status_frame = QHBoxLayout()
        
        self.status_label = QLabel("就绪")
        self.status_label.setFont(QFont("Microsoft YaHei", 10))
        self.status_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        
        self.speed_label = QLabel("速度: 0 IP/秒")
        self.speed_label.setFont(QFont("Microsoft YaHei", 10))
        self.speed_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        
        self.eta_label = QLabel("剩余时间: --")
        self.eta_label.setFont(QFont("Microsoft YaHei", 10))
        self.eta_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        
        status_frame.addWidget(self.status_label)
        status_frame.addStretch()
        status_frame.addWidget(self.speed_label)
        status_frame.addWidget(self.eta_label)
        
        main.addLayout(status_frame)

        status_display_label = QLabel("扫描状态和统计信息")
        status_display_label.setFont(QFont("Microsoft YaHei", 12))
        status_display_label.setStyleSheet("color:#1E3A8A;")
        main.addWidget(status_display_label)

        self.status_display = QTextEdit()
        self.status_display.setFont(FONT_STATUS)
        self.status_display.setMaximumHeight(180)
        self.status_display.setReadOnly(True)
        self.status_display.setStyleSheet("""
            QTextEdit {
                background:#0B3C5D;
                border:1px solid #0F4C75;
                border-radius:6px;
                padding:10px;
                color:#ECF0F1;
                font-size: 9pt;
            }
        """)
        main.addWidget(self.status_display)

        speed_results_label = QLabel("测速结果")
        speed_results_label.setFont(QFont("Microsoft YaHei", 12))
        speed_results_label.setStyleSheet("color:#1E3A8A;")
        main.addWidget(speed_results_label)

        self.speed_table = QTableWidget()
        self.speed_table.setColumnCount(6)
        self.speed_table.setHorizontalHeaderLabels(["排名", "IP地址", "地区码", "延迟", "下载速度", "测速类型"])
        
        header_font = QFont("Microsoft YaHei", 9)
        self.speed_table.horizontalHeader().setFont(header_font)
        
        table_font = QFont("Microsoft YaHei", 9)
        self.speed_table.setFont(table_font)
        
        self.speed_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.speed_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.speed_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.speed_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.speed_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.speed_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        
        self.speed_table.verticalHeader().setVisible(False)
        
        self.speed_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        self.speed_table.setStyleSheet("""
            QTableWidget {
                background:#0B3C5D;
                border-radius:8px;
                color:white;
                gridline-color:#1E4D6B;
                font-size: 9pt;
            }
            QHeaderView::section {
                background:#0F4C75;
                color:white;
                border:none;
                height:28px;
                padding-left:10px;
                font-size: 9pt;
            }
            QTableWidget::item {
                padding:4px;
                border-bottom:1px solid #1E4D6B;
                font-size: 9pt;
            }
            QTableWidget::item:selected {
                background:#1E4D6B;
            }
        """)
        
        self.speed_table.cellDoubleClicked.connect(self.copy_table_cell)
        
        main.addWidget(self.speed_table, 1)
    
    def region_text_changed(self, text):
        cursor_pos = self.input_region.cursorPosition()
        
        upper_text = text.upper()
        
        if text != upper_text:
            self.input_region.setText(upper_text)
            self.input_region.setCursorPosition(cursor_pos)
    
    def copy_table_cell(self, row, column):
        item = self.speed_table.item(row, column)
        if item:
            clipboard = QApplication.clipboard()
            clipboard.setText(item.text())
            self.status_display.append(f"已复制: {item.text()}")
    
    def start_ipv4_scan(self):
        if self.scanning or self.speed_testing:
            return
        
        self.scanning = True
        self.update_ui_state(task_started=True)
        
        self.scan_results = []
        self.speed_table.setRowCount(0)
        self.status_display.clear()
        self.status_display.append("=" * 30)
        
        self.progress_bar.setValue(0)
        self.status_label.setText("扫描中...")
        self.status_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.speed_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.eta_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.speed_label.setText("速度: 0 IP/秒")
        self.eta_label.setText("剩余时间: --")
        
        self.scan_worker = ScanWorker()
        self.scan_worker.progress_update.connect(self.update_progress)
        self.scan_worker.status_message.connect(self.update_status_message)
        self.scan_worker.scan_completed.connect(self.scan_finished)
        self.scan_worker.finished.connect(lambda: self.worker_finished("scan"))
        
        self.scan_worker.start()
    
    def start_full_speed_test(self):
        if self.speed_testing or self.scanning:
            return
        
        if not self.scan_results:
            self.status_display.append("错误：请先运行扫描获取IP列表！")
            return
        
        self.speed_testing = True
        self.update_ui_state(task_started=True)
        
        self.speed_table.setRowCount(0)
        self.status_display.append("=" * 30)
        self.status_display.append("开始完全测速...")
        
        self.progress_bar.setValue(0)
        self.status_label.setText("完全测速中...")
        self.status_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.speed_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.eta_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.speed_label.setText("测速进度: 0/5")
        self.eta_label.setText("预计时间: 约15秒")
        
        self.speed_test_worker = SpeedTestWorker(self.scan_results)
        self.speed_test_worker.progress_update.connect(self.update_speed_test_progress)
        self.speed_test_worker.status_message.connect(self.update_status_message)
        self.speed_test_worker.speed_test_completed.connect(self.speed_test_finished)
        self.speed_test_worker.finished.connect(lambda: self.worker_finished("speed_test"))
        
        self.speed_test_worker.start()
    
    def start_region_speed_test(self):
        if self.speed_testing or self.scanning:
            return
        
        if not self.scan_results:
            self.status_display.append("错误：请先运行扫描获取IP列表！")
            return
        
        region_code = self.input_region.text().strip().upper()
        if not region_code:
            self.status_display.append("错误：请输入地区码（如SJC、SIN等）")
            return
        
        if region_code not in AIRPORT_CODES:
            self.status_display.append(f"警告：地区码 {region_code} 不在已知列表中，将继续尝试测速")
        
        self.speed_testing = True
        self.update_ui_state(task_started=True)
        
        self.speed_table.setRowCount(0)
        self.status_display.append("=" * 30)
        self.status_display.append(f"开始地区测速: {region_code} ({AIRPORT_CODES.get(region_code, '未知地区')})")
        
        self.progress_bar.setValue(0)
        self.status_label.setText(f"{region_code}地区测速中...")
        self.status_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.speed_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.eta_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
        self.speed_label.setText("测速进度: 0/5")
        self.eta_label.setText("预计时间: 约15秒")
        
        self.speed_test_worker = SpeedTestWorker(self.scan_results, region_code)
        self.speed_test_worker.progress_update.connect(self.update_speed_test_progress)
        self.speed_test_worker.status_message.connect(self.update_status_message)
        self.speed_test_worker.speed_test_completed.connect(self.speed_test_finished)
        self.speed_test_worker.finished.connect(lambda: self.worker_finished("speed_test"))
        
        self.speed_test_worker.start()
    
    def stop_all_tasks(self):
        if self.scan_worker and self.scanning:
            self.scan_worker.stop()
            self.status_label.setText("正在停止扫描...")
            self.status_display.append("用户请求停止扫描...")
        
        if self.speed_test_worker and self.speed_testing:
            self.speed_test_worker.stop()
            self.status_label.setText("正在停止测速...")
            self.status_display.append("用户请求停止测速...")
        
        self.btn_stop.setEnabled(False)
    
    def scan_finished(self, results):
        self.scan_results = results
        
        self.show_scan_summary(results)
    
    def speed_test_finished(self, results):
        self.add_speed_results_to_table(results)
    
    def worker_finished(self, worker_type):
        if worker_type == "scan":
            self.scanning = False
            self.status_label.setText("扫描完成")
            if self.scan_results:
                self.btn_full.setEnabled(True)
                self.btn_area.setEnabled(True)
        
        elif worker_type == "speed_test":
            self.speed_testing = False
            self.status_label.setText("测速完成")
        
        if not self.scanning and not self.speed_testing:
            self.status_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
            self.speed_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
            self.eta_label.setStyleSheet("color:#1E3A8A; padding: 5px;")
            self.update_ui_state(task_started=False)
    
    def update_ui_state(self, task_started=False):
        if task_started:
            self.btn_stop.setEnabled(True)
            self.btn_ipv4.setEnabled(False)
            self.btn_full.setEnabled(False)
            self.btn_area.setEnabled(False)
        else:
            self.btn_stop.setEnabled(False)
            self.btn_ipv4.setEnabled(True)
            if self.scan_results:
                self.btn_full.setEnabled(True)
                self.btn_area.setEnabled(True)
            
            self.progress_bar.setValue(0)
    
    def update_progress(self, current, total, success_count, speed, eta):
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
        
        self.status_label.setText(f"扫描中: {success_count}个IP可用")
        self.speed_label.setText(f"速度: {speed:.1f} IP/秒")
        
        if eta < 60:
            eta_text = f"{eta:.0f}秒"
        elif eta < 3600:
            eta_text = f"{eta/60:.1f}分钟"
        else:
            eta_text = f"{eta/3600:.1f}小时"
        self.eta_label.setText(f"剩余时间: {eta_text}")
    
    def update_speed_test_progress(self, current, total, speed):
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
        
        self.status_label.setText(f"测速中: {current}/{total}")
        self.speed_label.setText(f"测速进度: {current}/{total}")
        
        if speed > 0:
            self.eta_label.setText(f"下载速度: {speed} MB/s")
    
    def update_status_message(self, message):
        self.status_display.append(message)
        
        scrollbar = self.status_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def show_scan_summary(self, results):
        if not results:
            self.status_display.append("")
            self.status_display.append("扫描完成！未找到任何可用IP地址。")
            return
        
        iata_stats = {}
        for result in results:
            iata_code = result.get('iata_code', '未知')
            if iata_code:
                key = f"{iata_code} ({result['chinese_name']})"
                iata_stats[key] = iata_stats.get(key, 0) + 1
        
        self.status_display.append("")
        self.status_display.append("扫描完成！！！")
        self.status_display.append(f"可用IP数: {len(results)}")
        self.status_display.append("")
        
        if iata_stats:
            self.status_display.append(f"地区统计（共 {len(iata_stats)} 个不同地区）:")
            sorted_iata = sorted(iata_stats.items(), key=lambda x: x[1], reverse=True)
            
            for iata, count in sorted_iata:
                self.status_display.append(f"  {iata}: {count}个IP")
        
        self.status_display.append("")
        self.status_display.append("现在可以使用完全测速或地区测速功能。")
    
    def add_speed_results_to_table(self, results):
        if not results:
            self.status_display.append("测速完成：没有有效的测速结果")
            return
        
        self.speed_table.setRowCount(0)
        
        for i, result in enumerate(results, 1):
            row = self.speed_table.rowCount()
            self.speed_table.insertRow(row)
            
            rank_item = QTableWidgetItem(str(i))
            rank_item.setTextAlignment(Qt.AlignCenter)
            
            ip_item = QTableWidgetItem(result['ip'])
            ip_item.setTextAlignment(Qt.AlignCenter)
            
            iata_code = result.get('iata_code', '未知')
            iata_item = QTableWidgetItem(iata_code)
            iata_item.setTextAlignment(Qt.AlignCenter)
            
            latency = result.get('latency', 0)
            latency_item = QTableWidgetItem(f"{latency:.2f}")
            latency_item.setTextAlignment(Qt.AlignCenter)
            
            if latency < 100:
                latency_item.setForeground(QColor("#22C55E"))
            elif latency < 200:
                latency_item.setForeground(QColor("#F59E0B"))
            else:
                latency_item.setForeground(QColor("#EF4444"))
            
            download_speed = result.get('download_speed', 0)
            speed_item = QTableWidgetItem(f"{download_speed:.2f}")
            speed_item.setTextAlignment(Qt.AlignCenter)
            
            if download_speed > 20:
                speed_item.setForeground(QColor("#22C55E"))
            elif download_speed > 10:
                speed_item.setForeground(QColor("#F59E0B"))
            elif download_speed > 5:
                speed_item.setForeground(QColor("#F97316"))
            else:
                speed_item.setForeground(QColor("#EF4444"))
            
            test_type = result.get('test_type', '未知')
            type_item = QTableWidgetItem(test_type)
            type_item.setTextAlignment(Qt.AlignCenter)
            
            self.speed_table.setItem(row, 0, rank_item)
            self.speed_table.setItem(row, 1, ip_item)
            self.speed_table.setItem(row, 2, iata_item)
            self.speed_table.setItem(row, 3, latency_item)
            self.speed_table.setItem(row, 4, speed_item)
            self.speed_table.setItem(row, 5, type_item)
        
        self.speed_table.scrollToBottom()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Microsoft YaHei"))
    
    icon_paths = [
        "cfs.ico",
        os.path.join(os.path.dirname(__file__), "cfs.ico"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfs.ico"),
    ]
    
    app_icon_set = False
    for icon_path in icon_paths:
        if os.path.exists(icon_path):
            try:
                app.setWindowIcon(QIcon(icon_path))
                app_icon_set = True
                break
            except Exception:
                continue
    
    if not app_icon_set:
        try:
            icon_path = os.path.join(sys._MEIPASS, "cfs.ico") if hasattr(sys, '_MEIPASS') else "cfs.ico"
            app.setWindowIcon(QIcon(icon_path))
        except Exception:
            pass
    
    win = CloudflareScanUI()
    win.show()
    sys.exit(app.exec())