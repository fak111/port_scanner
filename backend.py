#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
局域网端口扫描器 - 后端API (支持多用户并发 + 代理质量检测)
提供RESTful API接口
"""
from flask_cors import CORS # 导入 CORS
from flask import Flask, jsonify, request
from flask_cors import CORS
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import threading
import uuid
import time
import requests

app = Flask(__name__)
CORS(app)

# 使用字典存储多个扫描任务
scan_tasks = {}
# 任务清理线程锁
tasks_lock = threading.Lock()


class ScanTask:
    """扫描任务类"""

    def __init__(self, task_id, network, port, threads, check_proxy_quality=False):
        self.task_id = task_id
        self.network = network
        self.port = port
        self.threads = threads
        self.check_proxy_quality = check_proxy_quality
        self.is_scanning = False
        self.progress = 0
        self.total = 0
        self.scanned = 0
        self.results = []
        self.start_time = None
        self.end_time = None
        self.error = None
        self.created_at = datetime.now()

    def to_dict(self):
        """转换为字典"""
        return {
            'task_id': self.task_id,
            'network': self.network,
            'port': self.port,
            'threads': self.threads,
            'check_proxy_quality': self.check_proxy_quality,
            'is_scanning': self.is_scanning,
            'progress': self.progress,
            'total': self.total,
            'scanned': self.scanned,
            'results': self.results,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'error': self.error,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


def test_ai_model_availability(proxies, timeout=8):
    """
    测试主流AI模型的可用性
    检测 ChatGPT, Claude, Gemini 等模型是否可访问
    """
    ai_availability = {
        'chatgpt': {'available': False, 'status': 'unknown', 'response_time': None},
        'claude': {'available': False, 'status': 'unknown', 'response_time': None},
        'gemini': {'available': False, 'status': 'unknown', 'response_time': None},
        'copilot': {'available': False, 'status': 'unknown', 'response_time': None},
    }

    # 各个AI模型的测试端点
    ai_endpoints = [
        {
            'name': 'chatgpt',
            'url': 'https://chat.openai.com',
            'display_name': 'ChatGPT',
            'check_text': 'openai'  # 检查响应中是否包含关键字
        },
        {
            'name': 'claude',
            'url': 'https://claude.ai',
            'display_name': 'Claude',
            'check_text': 'claude'
        },
        {
            'name': 'gemini',
            'url': 'https://gemini.google.com',
            'display_name': 'Gemini',
            'check_text': 'google'
        },
        {
            'name': 'copilot',
            'url': 'https://copilot.microsoft.com',
            'display_name': 'Copilot',
            'check_text': 'microsoft'
        },
    ]

    for endpoint in ai_endpoints:
        try:
            start_time = time.time()
            response = requests.get(
                endpoint['url'],
                proxies=proxies,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
            )
            elapsed = time.time() - start_time

            # 判断是否可访问
            if response.status_code in [200, 301, 302]:
                # 检查是否被重定向到错误页面或地区限制页面
                content_lower = response.text.lower()

                # 常见的地区限制关键词
                blocked_keywords = [
                    'not available in your country',
                    'not available in your region',
                    'service is not available',
                    'access denied',
                    'region restricted',
                    'geographic restriction',
                    'geoblocked',
                    'vpn detected',
                    'proxy detected'
                ]

                is_blocked = any(keyword in content_lower for keyword in blocked_keywords)

                if is_blocked:
                    ai_availability[endpoint['name']]['available'] = False
                    ai_availability[endpoint['name']]['status'] = 'blocked'
                elif endpoint['check_text'] in content_lower or response.status_code == 200:
                    ai_availability[endpoint['name']]['available'] = True
                    ai_availability[endpoint['name']]['status'] = 'available'
                    ai_availability[endpoint['name']]['response_time'] = round(elapsed * 1000, 2)
                else:
                    ai_availability[endpoint['name']]['status'] = 'uncertain'

            elif response.status_code == 403:
                ai_availability[endpoint['name']]['available'] = False
                ai_availability[endpoint['name']]['status'] = 'blocked'
            else:
                ai_availability[endpoint['name']]['status'] = f'http_{response.status_code}'

        except requests.exceptions.Timeout:
            ai_availability[endpoint['name']]['status'] = 'timeout'
        except requests.exceptions.ConnectionError:
            ai_availability[endpoint['name']]['status'] = 'connection_error'
        except Exception as e:
            ai_availability[endpoint['name']]['status'] = 'error'

    return ai_availability


def test_proxy_quality(ip, port, timeout=8, check_ai_models=True):
    """
    测试代理质量 - 专门测试访问外网能力
    优化速度 + 检测代理出口IP的国家 + AI模型可用性
    """
    proxy_info = {
        'response_time': None,
        'is_working': False,
        'http_code': None,
        'can_access_google': False,
        'accessible_sites': [],
        'quality_score': 0,
        'quality_level': 'unknown',
        'error': None,
        'proxy_type': 'unknown',
        'exit_ip': None,
        'exit_country': None,
        'exit_country_code': None,
        'exit_city': None,
        'ai_models': None
    }

    # 测试多种代理协议
    proxy_configs = [
        {
            'type': 'http',
            'proxies': {
                'http': f'http://{ip}:{port}',
                'https': f'http://{ip}:{port}'
            }
        },
        {
            'type': 'socks5',
            'proxies': {
                'http': f'socks5://{ip}:{port}',
                'https': f'socks5://{ip}:{port}'
            }
        }
    ]

    # 优化：只测试关键站点，减少测试数量
    test_sites = [
        {'url': 'https://ipapi.co/json/', 'name': 'IP Check', 'key': 'ip_check', 'priority': 1},  # 获取出口IP和地理位置
        {'url': 'https://www.google.com/generate_204', 'name': 'Google', 'key': 'can_access_google', 'priority': 2},
        {'url': 'https://www.youtube.com', 'name': 'YouTube', 'key': 'can_access_youtube', 'priority': 3},
    ]

    best_time = None
    successful_config = None
    working_proxies = None

    # 尝试不同的代理配置
    for config in proxy_configs:
        proxies = config['proxies']

        # 按优先级测试
        for site in sorted(test_sites, key=lambda x: x['priority']):
            try:
                start_time = time.time()
                response = requests.get(
                    site['url'],
                    proxies=proxies,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                )
                elapsed = time.time() - start_time

                # 如果成功访问
                if response.status_code in [200, 204, 301, 302, 403]:
                    proxy_info['is_working'] = True
                    proxy_info['http_code'] = response.status_code
                    proxy_info['proxy_type'] = config['type']
                    working_proxies = proxies

                    if successful_config is None:
                        successful_config = config['type']

                    # 获取出口IP和地理位置信息（使用ipapi.co）
                    if site['key'] == 'ip_check' and response.status_code == 200:
                        try:
                            geo_data = response.json()
                            proxy_info['exit_ip'] = geo_data.get('ip')
                            proxy_info['exit_country'] = geo_data.get('country_name')
                            proxy_info['exit_country_code'] = geo_data.get('country_code')
                            proxy_info['exit_city'] = geo_data.get('city')
                            proxy_info['exit_region'] = geo_data.get('region')
                            print(
                                f"  -> 出口IP: {proxy_info['exit_ip']}, 位置: {proxy_info['exit_city']}, {proxy_info['exit_country']}")
                        except Exception as e:
                            print(f"  -> 解析地理位置失败: {e}")

                    # 记录可访问的站点
                    if site['name'] not in proxy_info['accessible_sites'] and site['name'] != 'IP Check':
                        proxy_info['accessible_sites'].append(site['name'])

                    # 标记特定站点可访问
                    if site['key'] in proxy_info:
                        proxy_info[site['key']] = True

                    # 记录最快的响应时间
                    if best_time is None or elapsed < best_time:
                        best_time = elapsed
                        proxy_info['response_time'] = round(elapsed * 1000, 2)

            except requests.exceptions.ProxyError:
                proxy_info['error'] = 'Proxy connection failed'
            except requests.exceptions.Timeout:
                proxy_info['error'] = 'Request timeout'
            except requests.exceptions.SSLError:
                proxy_info['error'] = 'SSL error'
            except requests.exceptions.ConnectionError:
                proxy_info['error'] = 'Connection error'
            except Exception as e:
                proxy_info['error'] = str(e)

        # 如果找到可用的配置就停止
        if proxy_info['is_working']:
            break

    # 如果代理可用且需要检测AI模型，则进行检测
    if proxy_info['is_working'] and check_ai_models and working_proxies:
        print(f"  -> 检测AI模型可用性...")
        proxy_info['ai_models'] = test_ai_model_availability(working_proxies, timeout)

        # 统计可用的AI模型数量
        available_models = [name for name, info in proxy_info['ai_models'].items() if info['available']]
        if available_models:
            print(f"  -> 可用AI模型: {', '.join(available_models)}")

    # 计算质量分数 (0-100)
    if proxy_info['is_working']:
        score = 30  # 基础分 - 能工作

        # 可访问的外网站点数量 (0-30分)
        accessible_count = len(proxy_info['accessible_sites'])
        if accessible_count >= 3:
            score += 30
        elif accessible_count >= 2:
            score += 25
        elif accessible_count >= 1:
            score += 20

        # 响应时间评分 (0-30分)
        if proxy_info['response_time'] is not None:
            if proxy_info['response_time'] < 300:
                score += 30  # 超快
            elif proxy_info['response_time'] < 600:
                score += 25  # 很快
            elif proxy_info['response_time'] < 1000:
                score += 20  # 快
            elif proxy_info['response_time'] < 2000:
                score += 15  # 中等
            elif proxy_info['response_time'] < 3000:
                score += 10  # 较慢
            elif proxy_info['response_time'] < 5000:
                score += 5  # 很慢

        # AI模型可用性加分 (0-10分)
        if proxy_info['ai_models']:
            available_models_count = sum(1 for info in proxy_info['ai_models'].values() if info['available'])
            if available_models_count >= 4:
                score += 10
            elif available_models_count >= 3:
                score += 8
            elif available_models_count >= 2:
                score += 6
            elif available_models_count >= 1:
                score += 4

        proxy_info['quality_score'] = score

        # 质量等级 - 针对翻墙代理
        if score >= 85:
            proxy_info['quality_level'] = 'excellent'  # 优秀
        elif score >= 70:
            proxy_info['quality_level'] = 'good'  # 良好
        elif score >= 55:
            proxy_info['quality_level'] = 'fair'  # 一般
        elif score >= 40:
            proxy_info['quality_level'] = 'poor'  # 较差
        else:
            proxy_info['quality_level'] = 'bad'  # 很差
    else:
        proxy_info['quality_level'] = 'unavailable'  # 不可用

    return proxy_info


def scan_port(ip, port, check_quality=False, timeout=1):
    """扫描单个IP的指定端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()

        if result == 0:
            base_result = {
                'ip': str(ip),
                'port': port,
                'status': 'open',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # 如果需要检测代理质量
            if check_quality:
                print(f"正在检测代理质量: {ip}:{port} (测试外网访问+地理位置)")
                proxy_quality = test_proxy_quality(str(ip), port)
                base_result.update({
                    'proxy_quality': proxy_quality,
                    'is_proxy_working': proxy_quality['is_working'],
                    'response_time': proxy_quality['response_time'],
                    'quality_score': proxy_quality['quality_score'],
                    'quality_level': proxy_quality['quality_level'],
                    'accessible_sites': proxy_quality['accessible_sites'],
                    'can_access_google': proxy_quality['can_access_google'],
                    'proxy_type': proxy_quality['proxy_type'],
                    'exit_ip': proxy_quality['exit_ip'],
                    'exit_country': proxy_quality['exit_country'],
                    'exit_country_code': proxy_quality['exit_country_code'],
                    'exit_city': proxy_quality['exit_city'],
                    'ai_models': proxy_quality['ai_models']
                })

            return base_result
    except Exception as e:
        pass
    return None


def scan_network_thread(task_id):
    """后台扫描线程"""
    with tasks_lock:
        if task_id not in scan_tasks:
            return
        task = scan_tasks[task_id]

    task.is_scanning = True
    task.start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        network_obj = ipaddress.ip_network(task.network, strict=False)
        total_hosts = network_obj.num_addresses
        task.total = total_hosts

        with ThreadPoolExecutor(max_workers=task.threads) as executor:
            futures = [
                executor.submit(scan_port, ip, task.port, task.check_proxy_quality)
                for ip in network_obj.hosts()
            ]

            for future in futures:
                result = future.result()
                task.scanned += 1
                task.progress = int((task.scanned / total_hosts) * 100)

                if result:
                    task.results.append(result)

    except Exception as e:
        print(f"扫描错误 (Task {task_id}): {e}")
        task.error = str(e)

    finally:
        task.is_scanning = False
        task.end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 如果启用了代理检测，对结果按质量分数排序
        if task.check_proxy_quality and task.results:
            task.results.sort(key=lambda x: x.get('quality_score', 0), reverse=True)


def cleanup_old_tasks():
    """清理超过1小时的旧任务"""
    while True:
        time.sleep(300)  # 每5分钟清理一次
        with tasks_lock:
            current_time = datetime.now()
            tasks_to_remove = []

            for task_id, task in scan_tasks.items():
                if not task.is_scanning:
                    age = (current_time - task.created_at).total_seconds()
                    if age > 3600:  # 1小时
                        tasks_to_remove.append(task_id)

            for task_id in tasks_to_remove:
                del scan_tasks[task_id]
                print(f"清理旧任务: {task_id}")


# 启动清理线程
cleanup_thread = threading.Thread(target=cleanup_old_tasks, daemon=True)
cleanup_thread.start()


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """
    启动新的扫描任务
    POST /api/scan
    Body: {
        "network": "10.16.65.0/24",
        "port": 7890,
        "threads": 50,
        "check_proxy_quality": true  # 是否检测代理质量
    }
    """
    try:
        data = request.json
        network = data.get('network', '10.16.65.0/24')
        port = int(data.get('port', 7890))
        threads = int(data.get('threads', 50))
        check_proxy_quality = data.get('check_proxy_quality', False)

        # 验证网络地址
        ipaddress.ip_network(network, strict=False)

        # 验证端口范围
        if not (1 <= port <= 65535):
            return jsonify({
                'status': 'error',
                'message': '端口号必须在1-65535之间'
            }), 400

        # 创建新任务
        task_id = str(uuid.uuid4())
        task = ScanTask(task_id, network, port, threads, check_proxy_quality)

        with tasks_lock:
            scan_tasks[task_id] = task

        # 启动后台扫描线程
        thread = threading.Thread(target=scan_network_thread, args=(task_id,))
        thread.daemon = True
        thread.start()

        return jsonify({
            'status': 'success',
            'task_id': task_id,
            'message': '扫描任务已创建' + (' (含代理质量检测)' if check_proxy_quality else ''),
            'data': task.to_dict()
        })

    except ValueError as e:
        return jsonify({
            'status': 'error',
            'message': f'参数错误: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'创建任务失败: {str(e)}'
        }), 500


@app.route('/api/task/<task_id>', methods=['GET'])
def get_task_status(task_id):
    """获取指定任务的状态"""
    with tasks_lock:
        if task_id not in scan_tasks:
            return jsonify({
                'status': 'error',
                'message': '任务不存在或已过期'
            }), 404

        task = scan_tasks[task_id]

    return jsonify({
        'status': 'success',
        'data': task.to_dict()
    })


@app.route('/api/tasks', methods=['GET'])
def get_all_tasks():
    """获取所有任务列表"""
    with tasks_lock:
        tasks_list = [task.to_dict() for task in scan_tasks.values()]

    return jsonify({
        'status': 'success',
        'total': len(tasks_list),
        'data': tasks_list
    })


@app.route('/api/task/<task_id>/results', methods=['GET'])
def get_task_results(task_id):
    """获取指定任务的扫描结果"""
    with tasks_lock:
        if task_id not in scan_tasks:
            return jsonify({
                'status': 'error',
                'message': '任务不存在'
            }), 404

        task = scan_tasks[task_id]

    return jsonify({
        'status': 'success',
        'data': {
            'task_id': task_id,
            'results': task.results,
            'total': len(task.results),
            'is_scanning': task.is_scanning,
            'check_proxy_quality': task.check_proxy_quality
        }
    })


@app.route('/api/task/<task_id>', methods=['DELETE'])
def delete_task(task_id):
    """删除指定任务"""
    with tasks_lock:
        if task_id not in scan_tasks:
            return jsonify({
                'status': 'error',
                'message': '任务不存在'
            }), 404

        task = scan_tasks[task_id]

        if task.is_scanning:
            return jsonify({
                'status': 'error',
                'message': '任务正在扫描中，无法删除'
            }), 400

        del scan_tasks[task_id]

    return jsonify({
        'status': 'success',
        'message': '任务已删除'
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """获取系统统计信息"""
    with tasks_lock:
        total_tasks = len(scan_tasks)
        active_tasks = sum(1 for task in scan_tasks.values() if task.is_scanning)
        completed_tasks = sum(1 for task in scan_tasks.values() if not task.is_scanning and task.end_time)

    return jsonify({
        'status': 'success',
        'data': {
            'total_tasks': total_tasks,
            'active_tasks': active_tasks,
            'completed_tasks': completed_tasks,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'success',
        'message': '服务运行正常',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


if __name__ == '__main__':
    print("=" * 60)
    print("局域网端口扫描器 - 后端API服务 (多用户版 + 代理检测)")
    print("=" * 60)
    print("API服务地址: http://localhost:5000")
    print("\nAPI端点:")
    print("  POST   /api/scan              - 创建新扫描任务")
    print("  GET    /api/task/<id>         - 获取任务状态")
    print("  GET    /api/task/<id>/results - 获取任务结果")
    print("  DELETE /api/task/<id>         - 删除任务")
    print("  GET    /api/tasks             - 获取所有任务")
    print("  GET    /api/stats             - 获取统计信息")
    print("  GET    /api/health            - 健康检查")
    print("\n新增功能:")
    print("  ✓ 翻墙代理质量检测 (优化速度)")
    print("  ✓ 代理出口IP地理位置检测 (国家/城市)")
    print("  ✓ AI模型可用性检测 (ChatGPT/Claude/Gemini/Copilot)")
    print("  ✓ 支持HTTP和SOCKS5代理")
    print("  ✓ 质量评分系统 (0-100分)")
    print("  ✓ 自动按质量排序")
    print("\n优化:")
    print("  ⚡ 减少测试站点数量，提升检测速度")
    print("  ⚡ 使用快速API端点")
    print("  ⚡ 智能检测地区限制")
    print("=" * 60)

    app.run(host='0.0.0.0', port=5000, debug=False)