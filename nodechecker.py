    import requests
    import urllib3
    from requests.exceptions import SSLError, RequestException
    import multiprocessing

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    def check_ip(ip):
        try:
            url = f'https://{ip}/cdn-cgi/trace'
            headers = {'Host': 'amarket.icu'}
            response = requests.get(url=url, headers=headers, verify=False, timeout=3)
            if response.status_code in (403, 200):
                return 'cloudflare' in response.text or 'colo' in response.text
        except SSLError:
            try:
                url = f'http://{ip}/cdn-cgi/trace'
                response = requests.get(url=url, headers=headers, verify=False, timeout=3)
                return response.status_code in (403, 200) and ('cloudflare' in response.text or 'colo' in response.text)
            except RequestException:
                return False
        except RequestException:
            return False


    def process_ip_list(ip_list):
        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
            results = pool.map(check_ip, ip_list)
        return [ip for ip, valid in zip(ip_list, results) if valid]


    def read_ip_list(file_path):
        with open(file_path, 'r') as file:
            return [line.strip('\n').split('//')[-1] for line in file.readlines()]


    def main():
        file_path = 'cf'  # 输入文件路径
        ip_list = read_ip_list(file_path)
        valid_ips = process_ip_list(ip_list)
        print(valid_ips)

        for ip in valid_ips:
            print(ip)


    if __name__ == '__main__':
        main()
