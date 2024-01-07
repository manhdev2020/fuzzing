import requests
import urllib
import argparse
import re
import validators
import concurrent.futures
import sys
import time
from bs4 import BeautifulSoup
import nmap
from colorama import Fore, init

init(autoreset=True) # Auto đặt lại style màu sau mỗi lần print về default
print(Fore.RED+r'''
      
        ██╗░░██╗███╗░░░███╗░█████╗░░░░░░░░█████╗░███████╗
        ██║░██╔╝████╗░████║██╔══██╗░░░░░░██╔═══╝░██╔════╝
        █████═╝░██╔████╔██║███████║█████╗██████╗░██████╗░
        ██╔═██╗░██║╚██╔╝██║██╔══██║╚════╝██╔══██╗╚════██╗
        ██║░╚██╗██║░╚═╝░██║██║░░██║░░░░░░╚█████╔╝██████╔╝
        ╚═╝░░╚═╝╚═╝░░░░░╚═╝╚═╝░░╚═╝░░░░░░░╚════╝░╚═════╝░            
                                                                   
                                                                Version 1.0
''')


def get_arguments(): # Hàm này dùng để lấy tham số truyền vào.
    parser = argparse.ArgumentParser() # sử dụng thư viện argparse để parse các tham số truyền vào ở dưới
    parser.add_argument('-u', '--url', dest='url', help='Url of target scan.') # Nếu t ruyền -u vào thì giá trị str sau đó sẽ được truyền vào biến url, còn khi dùng -h sẽ in ra nội dung của biến help
    parser.add_argument('-p', '--port', dest='port', help='Port of target scan.')
    parser.add_argument('-w', '--path', dest='path', help='Path file brute force.')
    parser.add_argument('-m', '--mod', dest='mod', help='SQLI, XSS')
    parser.add_argument('-P', '--processes', dest='processes', help='Processes (Default: 4).')
    parser.add_argument('-q', '--query', dest='query', help='Query search google_dork.')
    if len(sys.argv)==1: #Đoạn if này check xem có tham số nào được truyền vào khi chạy script hay không, nếu không thì sẽ in ra hướng dẫn sử dụng.
        parser.print_help(sys.stderr) # check nếu len(sys.argv)==1 thì có nghĩa là k có tham số nào truyền vào, trừ tên của đoạn script.
        sys.exit(1)
    options = parser.parse_args() # nếu có tham số truyền vào thì sẽ lưu trong biến options
    return options

def search_cve(vendor): #Tìm CVE dựa theo tên và phiên bản của server
    print('[*] CVE for server :')
    query = re.findall(r'[a-z0-9.\-]+', vendor) # Tìm cá từ có các chữ viết thường, chữ số, dấu . hoặc - trong vendor, sau đó append vào biến query.
    url = "https://cve.report/search.php?search={}".format(query[0]) # Url để search CVE dựa theo phiên bản server

    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')

    cve = soup.find_all('a')
    for i in cve:
        c = i.get('title')
        if c != None and 'CVE-' in c: #in ra các cve tìm được dựa theo respone trả về 
            print(c)
    print("-"*86)

def get_banner(url): # hàm này dùng để lấy banner của url truyền vào.
    print('_'*86)

    header = {'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36'}
    r = requests.get(url, headers=header)

    h = []
    with open('db/header.txt') as f:
        for x in f:
            h.append(x[:-1]) # append các  header ở file header.txt vào biến h
    for i in r.headers:
        if i in h: #check xem các header ở response có header nào trùng với các header trong h không, nếu có thì in ra nội dung
            print('[+] {} : {}'.format(i, r.headers[i]))

    if 'Server' in r.headers: # Nếu check ra được có header chứa từ 'server' thì sẽ search cve của server đó.
        print("-"*86)
        search_cve(r.headers['server'])

    lst = ['robots.txt', '.htaccess', '.DS_Store'] # list các file có thể chứa thông tin hay về hệ thống
    for i in lst:
        r2 = requests.get(url + "/" + i )
        if r2.status_code == 200: # request đến các file trong lst, nếu trả về 200 thì sẽ in ra ten + nội dung file.
            print('Found file {} !'.format(i))
            print(r2.text)
            print("-"*86)

    soup = BeautifulSoup(r.text, 'html.parser') # crawl data của trang web về
    print("[+] Find all input :")  
    input_data = soup.find_all('input') # sau đó tìm các trường input
    print(input_data)
    print("-"*86)
    print("[+] Find all tag meta :")
    meta_data = soup.find_all('meta') # tìm các trường meta
    print(meta_data)
    print("-"*86)

    links = re.findall('(?:href=")(.*?)"', r.text) # tìm các đường link trong trang web
    # đoạn regex bên dưới dùng để check format của url.
    regex_url = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    print("[+] Find all link in web {}\n".format(url))
    for l in set(links): # ỉn ra các url đã tìm được
        valid = re.findall(regex_url, l)
        if valid:
            print(l)

def load_file(url, path): # hàm này để load file wordlist, sau đó truyền hết vào biến lst
    lst = []
    with open(path) as f:
        for i in f:
            lst.append(url + i[:-1])
    return lst


def requestx(url_list): # hàm dùng để request, trả về response trong biến r
    USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0'
    header = {'User-agent': USER_AGENT}
    r = requests.get(url_list, headers=header)
    return r


def check_sqli(res, payload): # kiểm tra lỗ hổng sql injection thông qua response
    payload = re.findall(r'=.*\w', payload)
    if payload:  # This line checks if payload is not empty
        payload = payload[0][1:]
        if "mysql" in res.lower():
            print("Injectable MySQL detected,attack string: "+payload)
        elif "native client" in res.lower():
            print("Injectable MSSQL detected,attack string: "+payload)
        elif "syntax error" in res.lower():
            print("Injectable PostGRES detected,attack string: "+payload)
        elif "ORA" in res.lower():
            print("Injectable Oracle database detected,attack string: "+payload)
        else:
            print("---")

def check_xss(res, payload): # kiểm tra lỗ hổng xss thông qua response
    payload = re.findall(r'=.*\w', payload)
    payload = payload[0][1:]
    if str(payload).strip() in res.text:
        print("Payload - "+ payload +" - returned in the response")

def brute_force_page(url, path, processes, mod): # thực hiện fuzzing directory,  csqli và xss
    URLS = load_file(url, path) # load file wordlist đã được truyền ở tham số
    with concurrent.futures.ThreadPoolExecutor(max_workers=processes) as executor: #sử dụng concurrent.futures module để xử lý nhiều request đến các URL khác nhau sử dụng nhiều luồng
        future_to_url = {executor.submit(requestx, url_list): url_list for url_list in URLS} # requestx sẽ nhận một list các url như một tham số, mỗi lần gọi tới 
        # print("future done")
        for future in concurrent.futures.as_completed(future_to_url): #executor.submit(requestx, url_list) sẽ chuyển một danh sách khác nhau từ 'URLS' đến hàm 'requestsx'
            # print(future)
            urlx = future_to_url[future]
            # print("="*70)
            # print(Fore.GREEN+'[+] Checking %r' %(urlx))
            try:
                data = future.result()
                # print(data)
            except Exception as exc:
                print('%r generated an exception: %s' % (urlx, exc))
            else:
                if mod == None: # Nếu không có option mode thì sẽ chỉ fuzz directory
                    if data.status_code == 200:
                        print(Fore.GREEN+'[+] %r ------> %d' % (urlx, data.status_code))
                    elif data.status_code == 304:
                        print(Fore.RED+'[+] %r ------> %d' % (urlx, data.status_code))
                    elif data.status_code == 404:
                        print(Fore.RED+'[+] %r ------> %d' % (urlx, data.status_code))
                    elif data.status_code == 403:
                        print(Fore.RED+'[+] %r ------> %d' % (urlx, data.status_code))
                    elif data.status_code == 302:
                        print(Fore.YELLOW+'[+] %r ------> %d' % (urlx, data.status_code))
                if mod == 'sqli': # nếu mode là sqli thì sẽ fuzz SQLi
                    check_sqli(data.text, urlx)
                if mod == 'xss': # nếu mode là xss thì sẽ fuzz XSS
                    check_xss(data, urlx)
    print(Fore.GREEN+"*****Bruteforce directory done!*****")

def google_dork(query, url):# google dork theo url

    print('_'*70)
    print(Fore.BLUE+"[*] Find google dork {}\n".format(url))
    query = urllib.parse.quote(query) #URL encode
    URL = f"https://google.com/search?q={query}" #request đến google theo query ở trêb
    USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0'
    header = {'User-agent': USER_AGENT}
    resp = requests.get(URL, headers=header)
    if resp.status_code == 200:
        soup = BeautifulSoup(resp.text, "html.parser") # lấy response về sau đó parse html ra

    links  = soup.findAll('cite')
    for link in links:
        print('[+] ' + link.text)


def nmap_scan_host(host_scan, portlist): # scan nmap
    print(Fore.BLUE+'\n[*] Scanning nmap : {} \n'.format(host_scan))
    portScanner = nmap.PortScanner()
    h = re.findall(r'\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}', host_scan) # regex để lấy ip hoặc domain name
    portScanner.scan(hosts=h[0], arguments='-A -Pn vuln -p'+portlist) # truyền vào host, options nmap, port để scan

    hosts_list = [(x, portScanner[x]['status']['state']) for x in portScanner.all_hosts()] #lấy thông tin và status của các port trong host

    for host, status in hosts_list: # in ra host + status
        print(host, status)

        for protocol in portScanner[host].all_protocols():

            print(34*'-'+"Port Description"+34*'-')
            print('Protocol : %s' % protocol) # in ra protocol
            lport = portScanner[host][protocol].keys()
            for port in lport: # in ra tên, state của từng port trong list port
                state = portScanner[host][protocol][port]['state']
                name = portScanner[host][protocol][port]['name']
                print ('port : {}\tname : {}\tstate : {}'.format(port, name, state))

        if portScanner[host]['osmatch']:
            print('-'*35 + 'OS Description' +'-'*35)
            print("Details about the scanned host are: \t", portScanner[host]['osmatch'][0]['osclass'][0]['cpe']) # In ra các thông tin về OS
            print("Operating system family is: \t\t", portScanner[host]['osmatch'][0]['osclass'][0]['osfamily'])
            print("Type of OS is: \t\t\t\t", portScanner[host]['osmatch'][0]['osclass'][0]['type']) 
            print("Generation of Operating System :\t", portScanner[host]['osmatch'][0]['osclass'][0]['osgen'])
            print("Operating System Vendor is:\t\t", portScanner[host]['osmatch'][0]['osclass'][0]['vendor'])
            print("Accuracy of detection is:\t\t", portScanner[host]['osmatch'][0]['osclass'][0]['accuracy'])
      

def main():
    try:
        options = get_arguments() # lấy các tham số
        url = options.url 
        if options.mod == None:

            print(Fore.BLUE+'\n[*] Scanning url : {} \n'.format(url))
            get_banner(url)

            if options.query != None:
                google_dork(options.query,url)

            if options.path != None:
                print('_'*86)
                print(Fore.BLUE+'\n[*] Find hidden page : {} \n'.format(url))
                if options.processes != None:
                    pro = int(options.processes)
                else :
                    pro = 4
                brute_force_page(options.url, options.path, pro, None)
                            
            if options.port != None:
                nmap_scan_host(url, options.port)
        else:
            if options.path != None:
                print('_'*86)
                print(Fore.BLUE+'\n[*] Fuzzing {} : {} \n'.format(options.mod, url))
                if options.processes != None:
                    pro = int(options.processes)
                else :
                    pro = 4 #số luồng mặc định chạy là 4
                brute_force_page(options.url, options.path, pro, options.mod)

    except KeyboardInterrupt:
        print(Fore.RED + "[*] User interrupted the program.")
        raise SystemExit(0)

if __name__ == "__main__": 
    main()
