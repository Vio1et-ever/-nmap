一、简介
    本程序依靠nmap进行二次开发，目的是为了增加nmap的功能，使各位用的更舒服
二、前提
    由于本程序是依靠nmap开发的，所以要求电脑先有nmap；
    附下载链接：https://nmap.org/download.html
    请大家下载自己对应电脑系统的nmap
三、用法：
    本程序在保留nmap原有功能的同时，增加了存储扫描数据和梳理内网http资产；
    参数：
        -a    --arguments     使用nmap模块时调用的参数  如   -p http* -iL r.txt   扫描r.txt文本的IP地址  获取http服务的数据
        -T    --Type    这里是要使用的模式，当Type =1 时，只扫描端口，当Type=2时，将扫描到的http服务进行下一步验证，获取title值
        -t	  --thread_count  线程数量，当Type=2时 使用多线程 来请求http服务，获取title  默认 50
    扫描端口的使用方式：python port_scan.py -a "127.0.0.1 -p 0-65535" -T 1
    http资产梳理的使用方式：python port_scan.py -a "-p http* -iL r.txt" -T 2 -t 50
四、改进：
    扫描http服务，效率更高，准确率比全端口扫描要低,当然效率与搭建的服务器有关。
