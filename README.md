# nmap-python
## 本项目是通过python实现nmap功能

### 对于port_scan.py
1、简介
    本程序依靠nmap进行二次开发，目的是为了增加nmap的功能，使各位用的更舒服
2、前提
    由于本程序是依靠nmap开发的，所以要求电脑先有nmap；
    附下载链接：https://nmap.org/download.html
    请大家下载自己对应电脑系统的nmap
3、用法：
    本程序在保留nmap原有功能的同时，增加了存储扫描数据和梳理内网http资产；
    参数：
        -a    --arguments     使用nmap模块时调用的参数  如   -p http* -iL r.txt   扫描r.txt文本的IP地址  获取http服务的数据
        -T    --Type    这里是要使用的模式，当Type =1 时，只扫描端口，当Type=2时，将扫描到的http服务进行下一步验证，获取title值
        -t	  --thread_count  线程数量，当Type=2时 使用多线程 来请求http服务，获取title  默认 50
    扫描端口的使用方式：python port_scan.py -a "127.0.0.1 -p 0-65535" -T 1
    http资产梳理的使用方式：python port_scan.py -a "-p http* -iL r.txt" -T 2 -t 50
4、改进：
    扫描http服务，效率更高，准确率比全端口扫描要低,当然效率与搭建的服务器有关

对于repscan.py
1、简介
    本程序是由本人编写的，无依靠nmap，利用python来实现nmap的功能
2、用法
    本程序尽量还原了nmap的基础功能，增加了存储扫描数据和梳理内网http资产；
    参数：
        -T --Type 当Type=1时扫描端口，当Type=2时扫描http服务，默认为1
        -t --thread_count 线程数量，当Type=2时，使用多线程来请求http服务，获取title，默认50
        -i --ip 要扫描的IP地址
        -p --port 要扫描的指定端口或端口范围
        -f --filename 要保存的文件名（只需输入文件名，不用输入文件后缀，自动存为xlsx）
        -r --iplist 要扫描的含有IP地址的文件
        --sn 用ping扫描端口
    扫描端口的使用方式：
    1）指定端口，指定ip：python repscan.py -i 127.0.0.1 -p 8080 -T 1
    2）扫描端口范围，ip文件，将结果保存到portscan：
    python repscan.py -r "r.txt" -p 1-1024 -f "portscan" -T 1
    3）用ping扫描：python repscan.py --sn -i 127.0.0.1 -p 1-1024 
    4）扫描http服务：python repscan.py -i 127.0.0.1 -T 2 -t 50
3、改进：
    增加了扫描http服务，脱离nmap

对于rnmap.py
1、简介
    本程序是由本人编写的，利用python来实现nmap的功能
2、用法
    "-T", "--Type" T=1 scan port, T=2 scan http service
    "-i", "--ip" IP address to scan
    "-p", "--ports" Port range to scan, e.g., '1-1024'
    "-f", '--filename' filename
    "-r", "--ipfile" A file that contains an IP address
    "--sn" Scan the port with ping
    "--su" Use UDP for scanning
    扫描端口的使用方式：
    1）指定端口，指定IP：python rnmap.py -i 127.0.0.1 -p 8080 -T 1
    2) 范围扫描端口，IP文件，并将结果保存到portscan：
    python rnmap.py -r "r.txt" -p 1-1024 -f "portscan" -T 1
    3）用ping扫描：python rnmap.py --sn -i 127.0.0.1 -p 1-1024 
    4）扫描http服务：python rnmap.py -i 127.0.0.1 -T 2 
    5) 扫描udp服务：python rnmap.py -i 127.0.0.1
3、改进：
    1）相比于repscan.py，本程序采用异步编程来提高扫描效率
    2）在原有的功能基础上，增加了许多内容，比如protocol，service，udp，更贴合nmap

建议：
    1.如果本机装有nmap，使用port_scan.py
    2.没有nmap，建议使用rnmap.py,功能相同，效率有所提高，有保存扫描和梳理内网http资产的新功能，后续也将增加更多的功能
