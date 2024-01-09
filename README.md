# Nhóm 65 - Đề tài: Xây dựng công cụ Fuzzing trên Docker
## Installation
```
pip install -r requirement.txt
```
## Usage:

```
 ____  __.   _____      _____              ________ .________
|    |/ _|  /     \    /  _  \            /  _____/ |   ____/
|      <   /  \ /  \  /  /_\  \   ______ /   __  \  |____  \ 
|    |  \ /    Y    \/    |    \ /_____/ \  |__\  \ /       \
|____|__ \\____|__  /\____|__  /          \_____  //______  /
        \/        \/         \/                 \/        \/            
                                                                 
                                                                Version 1.0

usage: python main.py [-h] [-u URL] [-p PORT] [-r PATH] [-m MOD] [-P PROCESSES] [-q QUERY]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Url of target scan.
  -p PORT, --port PORT  Port of target scan.
  -w PATH, --path PATH  Path file brute force.
  -m MOD, --mod MOD     SQLI, XSS
  -P PROCESSES, --processes PROCESSES
                        Processes (Default: 4).
  -q QUERY, --query QUERY
                        Query search google_dork.

example:
SQLi testing       :  python main.py -u http://testphp.vulnweb.com/artists.php?artist= -w db/sqli.txt -m sqli
Google dorking     :  python main.py -u http://testphp.vulnweb.com/ -q inurl:"admin"
Fuzzing directory  :  python main.py -u http://testphp.vulnweb.com/ -w db/dicc.txt
Nmap               :  python main.py -u https://example.com -p 80,8080,8000
```

docker run -it --rm fuzz -u http://testphp.vulnweb.com/artists.php?artist= -w db/sqli.txt -m sqli
docker run -it --rm fuzz -u https://0a2c009e04e28a4f80d112c500470047.web-security-academy.net/?search= -w db/xss.txt -m xss
docker run -it --rm fuzz -u http://testphp.vulnweb.com -q inurl:"admin"
docker run -it --rm fuzz -u http://testphp.vulnweb.com/ -w db/dicc.txt
docker run -it --rm fuzz -u http://testphp.vulnweb.com/ -w db/dicc.txt
docker run -it --rm fuzz -u http://testphp.vulnweb.com -p 80,8000,8080