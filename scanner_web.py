#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
局域网端口扫描Web应用
提供实时扫描和结果展示的Web界面
"""

from flask import Flask, render_template_string, jsonify, request
from flask_cors import CORS
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import threading
import time

app = Flask(__name__)
CORS(app)

# 全局变量存储扫描状态
scan_status = {
    'is_scanning': False,
    'progress': 0,
    'total': 0,
    'scanned': 0,
    'results': [],
    'start_time': None,
    'end_time': None
}


def scan_port(ip, port, timeout=1):
    """扫描单个IP的指定端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()

        if result == 0:
            return {
                'ip': str(ip),
                'port': port,
                'status': 'open',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }
    except:
        pass
    return None


def scan_network_thread(network, port, threads):
    """后台扫描线程"""
    global scan_status

    scan_status['is_scanning'] = True
    scan_status['progress'] = 0
    scan_status['scanned'] = 0
    scan_status['results'] = []
    scan_status['start_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        total_hosts = network_obj.num_addresses
        scan_status['total'] = total_hosts

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(scan_port, ip, port)
                for ip in network_obj.hosts()
            ]

            for future in futures:
                result = future.result()
                scan_status['scanned'] += 1
                scan_status['progress'] = int((scan_status['scanned'] / total_hosts) * 100)

                if result:
                    scan_status['results'].append(result)

    except Exception as e:
        print(f"扫描错误: {e}")

    finally:
        scan_status['is_scanning'] = False
        scan_status['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>局域网端口扫描器</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .control-panel {
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            font-weight: 600;
            margin-bottom: 8px;
            color: #495057;
        }

        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }

        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }

        .form-row {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr;
            gap: 15px;
        }

        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .btn-primary:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }

        .progress-section {
            padding: 30px;
            display: none;
        }

        .progress-section.active {
            display: block;
        }

        .progress-bar-container {
            width: 100%;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin-bottom: 15px;
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #667eea;
        }

        .stat-card .label {
            color: #6c757d;
            font-size: 14px;
            margin-bottom: 5px;
        }

        .stat-card .value {
            color: #212529;
            font-size: 24px;
            font-weight: 700;
        }

        .results-section {
            padding: 30px;
        }

        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .results-header h2 {
            color: #212529;
        }

        .badge {
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: 600;
        }

        .results-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .results-table thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .results-table th,
        .results-table td {
            padding: 15px;
            text-align: left;
        }

        .results-table tbody tr:nth-child(even) {
            background: #f8f9fa;
        }

        .results-table tbody tr:hover {
            background: #e9ecef;
        }

        .status-badge {
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-open {
            background: #28a745;
            color: white;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
        }

        .empty-state svg {
            width: 100px;
            height: 100px;
            margin-bottom: 20px;
            opacity: 0.3;
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 局域网端口扫描器</h1>
            <p>实时扫描并监控网络端口状态</p>
        </div>

        <div class="control-panel">
            <div class="form-row">
                <div class="form-group">
                    <label for="network">网络地址 (CIDR格式)</label>
                    <input type="text" id="network" value="10.16.65.0/24" placeholder="例如: 192.168.1.0/24">
                </div>
                <div class="form-group">
                    <label for="port">目标端口</label>
                    <input type="number" id="port" value="7890" placeholder="端口号">
                </div>
                <div class="form-group">
                    <label for="threads">并发线程</label>
                    <input type="number" id="threads" value="50" placeholder="线程数">
                </div>
            </div>
            <button class="btn btn-primary" id="startBtn" onclick="startScan()">开始扫描</button>
        </div>

        <div class="progress-section" id="progressSection">
            <div class="progress-bar-container">
                <div class="progress-bar" id="progressBar">0%</div>
            </div>
            <div class="stats">
                <div class="stat-card">
                    <div class="label">扫描进度</div>
                    <div class="value" id="scannedCount">0 / 0</div>
                </div>
                <div class="stat-card">
                    <div class="label">发现开放</div>
                    <div class="value" id="openCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="label">扫描状态</div>
                    <div class="value" id="scanStatus">准备就绪</div>
                </div>
            </div>
        </div>

        <div class="results-section">
            <div class="results-header">
                <h2>扫描结果</h2>
                <span class="badge" id="resultCount">0 个结果</span>
            </div>
            <div id="resultsContainer">
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M12 6v6l4 2"></path>
                    </svg>
                    <h3>暂无扫描结果</h3>
                    <p>点击"开始扫描"按钮来开始网络扫描</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let updateInterval;

        function startScan() {
            const network = document.getElementById('network').value;
            const port = document.getElementById('port').value;
            const threads = document.getElementById('threads').value;
            const startBtn = document.getElementById('startBtn');

            startBtn.disabled = true;
            startBtn.textContent = '扫描中...';
            document.getElementById('progressSection').classList.add('active');
            document.getElementById('scanStatus').textContent = '扫描中...';
            document.getElementById('scanStatus').classList.add('pulse');

            fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({network, port: parseInt(port), threads: parseInt(threads)})
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'started') {
                    updateInterval = setInterval(updateStatus, 500);
                }
            });
        }

        function updateStatus() {
            fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                const progressBar = document.getElementById('progressBar');
                const scannedCount = document.getElementById('scannedCount');
                const openCount = document.getElementById('openCount');
                const scanStatus = document.getElementById('scanStatus');
                const resultCount = document.getElementById('resultCount');
                const startBtn = document.getElementById('startBtn');

                progressBar.style.width = data.progress + '%';
                progressBar.textContent = data.progress + '%';
                scannedCount.textContent = `${data.scanned} / ${data.total}`;
                openCount.textContent = data.results.length;
                resultCount.textContent = `${data.results.length} 个结果`;

                updateResultsTable(data.results);

                if (!data.is_scanning) {
                    clearInterval(updateInterval);
                    startBtn.disabled = false;
                    startBtn.textContent = '开始扫描';
                    scanStatus.textContent = '扫描完成';
                    scanStatus.classList.remove('pulse');
                }
            });
        }

        function updateResultsTable(results) {
            const container = document.getElementById('resultsContainer');

            if (results.length === 0) {
                return;
            }

            let html = `
                <table class="results-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>IP地址</th>
                            <th>端口</th>
                            <th>状态</th>
                            <th>发现时间</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            results.forEach((result, index) => {
                html += `
                    <tr>
                        <td>${index + 1}</td>
                        <td><strong>${result.ip}</strong></td>
                        <td>${result.port}</td>
                        <td><span class="status-badge status-open">${result.status}</span></td>
                        <td>${result.timestamp}</td>
                    </tr>
                `;
            });

            html += `
                    </tbody>
                </table>
            `;

            container.innerHTML = html;
        }
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    """主页"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """启动扫描"""
    global scan_status

    if scan_status['is_scanning']:
        return jsonify({'status': 'error', 'message': '扫描正在进行中'})

    data = request.json
    network = data.get('network', '10.16.65.0/24')
    port = data.get('port', 7890)
    threads = data.get('threads', 50)

    # 启动后台扫描线程
    thread = threading.Thread(target=scan_network_thread, args=(network, port, threads))
    thread.daemon = True
    thread.start()

    return jsonify({'status': 'started', 'message': '扫描已启动'})


@app.route('/api/status', methods=['GET'])
def get_status():
    """获取扫描状态"""
    return jsonify(scan_status)


if __name__ == '__main__':
    print("=" * 60)
    print("局域网端口扫描器 Web 服务")
    print("=" * 60)
    print("服务启动在: http://localhost:5002")
    print("请在浏览器中打开上述地址")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5002, debug=True)