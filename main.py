# coding:utf-8
import multiprocessing
from threading import Thread
import urllib3
from requests.exceptions import SSLError
import argparse
import subprocess
import re
import ip2asn
import logging
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pythonping import ping

# 定义两个列表来分别存储延迟和丢包数据
latency_data = []
loss_data = []

# 禁用 urllib3 的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

colo_list = []

speedtest_result = []


def thread_ping(ip):
    ping_result = ping(ip)
    latency = format(ping_result.rtt_avg * 1000, '.2f')  # 转换为毫秒并保留两位小数
    loss = (ping_result.stats_packets_lost) / 4  # 计算丢包率
    # 将数据添加到对应的列表中
    latency_data.append((ip, float(latency)))  # 存储为元组，便于排序
    loss_data.append((ip, loss))


class CustomHTTPSAdapter(HTTPAdapter):
    def __init__(self, hostname, ip, port=443, *args, **kwargs):
        self.hostname = hostname
        self.ip = ip
        self.port = port
        super(CustomHTTPSAdapter, self).__init__(*args, **kwargs)

    def get_connection(self, url, proxies=None):
        # 直接使用IP地址和端口创建HTTPS连接
        return HTTPSConnection(host=self.ip, port=self.port)

    def add_certs(self, request):
        # 禁用SSL证书验证
        request.cert_reqs = 'CERT_NONE'
        request.assert_hostname = self.hostname



def speed_test(url, ip, port, hostname, length, timeout):
    session = requests.Session()
    adapter = CustomHTTPSAdapter(hostname=hostname, ip=ip, port=port)
    session.mount(f'https://{hostname}', adapter)

    try:
        start_time = time.time()
        response = session.get(url, timeout=int(timeout))
        # 确保请求成功
        if response.status_code == 200:
            end_time = time.time()
            elapsed_time = end_time - start_time
            speed = length / elapsed_time if elapsed_time > 0 else 0
            print(f"节点 {ip} 测速结果：{elapsed_time:.2f} 秒, 平均速度：{speed:.2f} M/S")
            speedtest_result.append({'ip': ip, 'speed': speed})
        else:
            print(f"节点 {ip} 请求失败，状态码：{response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"节点 {ip} 请求异常：{e}")


class TracerouteLib:
    # TODO:这里的LIST是一股脑存进去 主函数里面再次去重 相当抽象 需要重构

    GOOD_ROUTE_LIST = []

    def __init__(self, ip2asn_db_path):
        self.i2a = ip2asn.IP2ASN(ip2asn_db_path)
        self.good_route_map = {
            4538: "CERNET",
            4837: "联通4837",
            9929: "联通9929",
            4809: "电信CN2",
            10099: "联通CUG",
            23764: "电信CTG",
            58807: "移动CMIN2"
        }

    def parse_traceroute_output(self, output):
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        return ip_pattern.findall(output)

    def execute_traceroute(self, target_host):
        command = ['tracert', '-d', '-w', '1', target_host]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise Exception(f"Traceroute failed for {target_host}: {e}")

    def get_traceroute_ips(self, target_host):
        output = self.execute_traceroute(target_host)
        return self.parse_traceroute_output(output) if output else []

    def traceroute_with_good_route_check(self, target_host, logger):
        logger.info(f"Starting traceroute for {target_host}")
        ips = self.get_traceroute_ips(target_host)
        if ips:
            good_routes_found = set()
            for ip in ips:
                try:
                    asn_data = self.i2a.lookup_address(ip)
                    asn = int(asn_data['ASN'])
                    owner = asn_data['owner']
                    route_name = self.good_route_map.get(asn, None)  # 使用None代替'Unknown ASN'作为默认值

                    # 记录日志信息
                    if route_name:
                        # 如果是优质ASN，记录优质路由名称
                        logger.info(f"IP: {ip}, ASN: {asn}, Owner: {owner}, Route: {route_name}")
                        good_routes_found.add(route_name)
                        self.GOOD_ROUTE_LIST.append({'ip': target_host, 'route': route_name})
                    else:
                        # 如果不是优质ASN，记录ASN编号
                        logger.info(f"IP: {ip}, ASN: {asn}, Owner: {owner}")
                except Exception as e:
                    logger.error(f"Error looking up IP {ip}: {e}")

            # 记录所有找到的优质路由名称
            if good_routes_found:
                good_routes_message = ", ".join(good_routes_found)
                logger.info(f"====Good Routes Found: {good_routes_message}====")
            else:
                logger.info("====No Good Route Found====")
        else:
            logger.error(f"No IPs found for {target_host}")


def setup_logger(logger_name, log_file):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    handler = logging.FileHandler(log_file, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def thread_traceroute(lib, target_host, logger):
    try:
        lib.traceroute_with_good_route_check(target_host, logger)
    except Exception as e:
        logger.error(f"Error for {target_host}: {e}")


def check_ip(ip):
    try:
        url = f'https://{ip}/cdn-cgi/trace'
        headers = {'Host': 'cloudflare.com'}
        response = requests.get(url=url, headers=headers, verify=False, timeout=3)
        if response.status_code in (403, 200):
            return 'cloudflare' in response.text or 'colo' in response.text
    except SSLError:
        try:
            url = f'http://{ip}/cdn-cgi/trace'
            response = requests.get(url=url, headers=headers, verify=False, timeout=3)
            return response.status_code in (403, 200) and ('cloudflare' in response.text or 'colo' in response.text)
        except:
            return False
    except:
        return False
    return False


def check_colo(ip):
    url = 'http://' + str(ip) + '/cdn-cgi/trace'
    try:
        res = requests.get(url, timeout=5)  # 设置超时时间
        pattern = r'colo=(\w+)'

        # 使用 re.search 来查找匹配项
        match = re.search(pattern, res.text)
        if match:
            extracted_value = match.group(1)
            return extracted_value
        else:
            return None
    except:
        return None



def worker(ip):
    colo_list.append({"ip": ip, "colo": check_colo(ip)})


def process_ip_list(ip_list):
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(check_ip, ip_list)
    return [ip for ip, valid in zip(ip_list, results) if valid]


def main(args):
    if args.colo:
        threads = []
        file = open(str(args.input), 'r')
        ips = file.readlines()  # 一次性读取所有IP地址

        # 创建并启动线程
        for ip in ips:
            ip = ip.strip('\n')
            thread = Thread(target=worker, args=(ip,))
            threads.append(thread)
            thread.start()

        file.close()
        for thread in threads:
            thread.join()

        file = open(str(args.output), 'w+')
        for item in colo_list:
            if item['colo']:
                print('IP:', item['ip'], 'Colo:', item['colo'])
                file.write('IP:' + item['ip'] + ' Colo:' + item['colo'] + '\n')
        file.close()

    elif args.node_list:
        with open(str(args.input), 'r') as file:
            ip_list = [line.strip('\n').split('//')[-1] for line in file.readlines()]
        valid_ips = process_ip_list(ip_list)
        file = open(str(args.output), 'a+')
        for ip in valid_ips:
            print(ip)
            file.write(ip + '\n')

    elif args.route:
        print('routecheck')
        targets = []  # 这里填入你的目标主机列表
        file = open(str(args.input), 'r')
        for line in file:
            targets.append(line.strip('\n'))
        file.close()
        ip2asn_db_path = args.ip2asn_db
        log_directory = "logs"  # 日志文件存放目录

        # 确保日志目录存在
        import os
        os.makedirs(log_directory, exist_ok=True)

        # 创建TracerouteLib实例
        lib = TracerouteLib(ip2asn_db_path)

        # 使用线程池执行traceroute操作
        with ThreadPoolExecutor(max_workers=len(targets)) as executor:
            for target in targets:
                logger_name = f"traceroute_{target}"
                log_file = os.path.join(log_directory, f"{target}.log")
                logger = setup_logger(logger_name, log_file)
                executor.submit(thread_traceroute, lib, target, logger)

        unique_dicts = set(frozenset(d.items()) for d in TracerouteLib.GOOD_ROUTE_LIST)

        # 将 frozenset 转换回字典列表
        unique_list_of_dicts = [dict(d) for d in unique_dicts]
        for item in unique_list_of_dicts:
            file = open(item["route"] + '_list.txt', "a+")
            file.write(f"{item['ip']}\n")
            file.close()
            # 同样，因为重复问题 暂时用try-except兜住了
            try:
                targets.remove(item['ip'])
            except ValueError:
                continue

        file = open('normal_list.txt', 'a+')
        for item in targets:
            file.write(f"{item}\n")
        file.close()
        print('SUCCESS!')

    elif args.speedtest:
        print('speedtest')
        file = open(str(args.input), 'r')
        length = int(args.length)
        nodes = []
        for line in file:
            nodes.append({"url": f"https://speedtest.sese.pics/{str(length)}M.dat", "ip": line.strip('\n'), "port": 443,
                          "hostname": "speedtest.sese.pics"})

        # 定义最大线程数
        MAX_THREADS = int(args.threads)
        timeout = args.timeout
        # 使用ThreadPoolExecutor创建线程池
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_node = {
                executor.submit(speed_test, node['url'], node['ip'], node['port'], node['hostname'], length,
                                timeout): node
                for node in nodes}

            # 等待所有任务完成
            for future in as_completed(future_to_node):
                try:
                    node = future_to_node[future]
                    future.result()  # 获取结果，如果任务抛出异常，将会在这里被抛出
                    # 这里可以添加处理结果的代码
                except Exception as e:
                    print(f"节点 {node['ip']} 测速失败: {e}")

            file = open(str(args.output), 'w+')
            speedtest_result.sort(key=lambda x: x['speed'], reverse=True)
            for item in speedtest_result:
                file.write('IP:' + str(item['ip']) + '     Speed:' + str(format(float(item['speed']), '.2f')) + 'M/S\n')
            file.close()

    elif args.latency:
        print('latency & loss')
        file = open(str(args.input), 'r')
        ips = [line.strip('\n') for line in file]  # 读取所有IP地址到列表中
        file.close()

        # 创建一个线程列表
        threads = []
        # 对每个IP地址创建一个线程
        for ip in ips:
            thread = Thread(target=thread_ping, args=(ip,))
            threads.append(thread)
            thread.start()  # 启动线程

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 分别对延迟和丢包数据进行排序
        sorted_latency_data = sorted(latency_data, key=lambda x: x[1])
        sorted_loss_data = sorted(loss_data, key=lambda x: x[1])

        file = open('latency_data.txt', 'w+')
        for ip, latency in sorted_latency_data:
            file.write(f"{ip}: {latency} ms \n")
        file.close()

        file = open('loss_data.txt', 'w+')
        for ip, loss in sorted_loss_data:
            file.write(f"{ip}: {loss * 100}% \n")
        file.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network traceroute and quality checking tool.')
    parser.add_argument('-i', '--input', required=True, type=str, help='Input file with target hosts (one per line).')
    parser.add_argument('-o', '--output', required=False, type=str, help='Output file to store the results.')

    parser.add_argument('-C', '--colo', action='store_true', help='Colo check mode.')

    parser.add_argument('-N', '--node_list', action='store_true',
                        help='Chek and Process the list of nodes from the input file.')

    parser.add_argument('-R', '--route', action='store_true',
                        help='Perform route trace for each target in the input file.')

    parser.add_argument('-S', '--speedtest', action='store_true',
                        help='Perform route trace for each target in the input file.')

    parser.add_argument('-L', '--latency', action='store_true',
                        help='Perform latency and package loss for each target in the input file.')

    parser.add_argument('-ip2asn_db', type=str, default='ip2asn-v4-u32.tsv', help='Path to the IP2ASN database file.')

    parser.add_argument('-length', type=int, default=10, help='File length for speedtest,default 10(MB). 5,10,'
                                                              '20 supported')
    parser.add_argument('--threads', type=int, default=10, help='Threads for speedtest,default 10,CHANGE WITH '
                                                                'CAUTION(ESPECIALLY WHEN YOUR BANDWIDTH IS LOW)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for speedtest default 10')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: Input file '{args.input}' not found.")
        exit(1)
    if (not (args.route or args.latency)) and (not args.output):
        print(f"Error: Output file not specified.")
        exit(1)
    main(args)
