import re
import requests
from threading import Thread


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
    except Exception as e:
        return None


def worker(ip):
    list.append({"ip": ip, "colo": check_colo(ip)})


threads = []
list = []

file = open('cnout', 'r')
ips = file.readlines()  # 一次性读取所有IP地址

# 创建并启动线程
for ip in ips:
    ip = ip.strip('\n')
    thread = Thread(target=worker, args=(ip,))
    threads.append(thread)
    thread.start()

# 等待所有线程完成
for thread in threads:
    thread.join()

file.close()
for item in list:
    if item['colo']:
        print('IP:', item['ip'], 'Colo:', item['colo'])
