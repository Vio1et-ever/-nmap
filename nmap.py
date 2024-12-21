from nmap_logic import *
import argparse
import re

parser = argparse.ArgumentParser(description='Port Scanner')
parser.add_argument('-i', '--ip',
                    help='Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24 or file with ip(txt))')
parser.add_argument('-p', '--ports', default="1-1024", help='Port range to scan (e.g., 20-80 or 22)')
parser.add_argument('--hp', action='store_true', help='HTTP scan')
parser.add_argument('-o', '--output', default='', help='Output filename (xlsx, txt)')
parser.add_argument('--sT', action='store_true', help='TCP connect')
parser.add_argument('--sU', action='store_true', help='UDP connect')
parser.add_argument('--sS', action='store_true', help='SYN connect')
parser.add_argument('--sn', action='store_true', help='ping scan but port')
parser.add_argument('--sP', action='store_true', help='ping scan with port')

args = parser.parse_args()

ip = args.ip
ports = args.ports
http = args.hp
filename = args.output
tcp = args.sT
udp = args.sU
gs_ip = args.sn
pp = args.sP
syn = args.sS

ip_list = []
data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
res = []
s = []

# 处理ip地址
if ".txt" in ip:
    # 获取IP地址
    with open(ip, 'r') as f:
        line = f.readline()
        while line:
            if "\n" in line:
                ip_list.append(line.split("\n")[0])
            else:
                ip_list.append(line)
            line = f.readline()

elif "/" in ip:
    if int(ip.split("/")[1]) >= 24:
        num = ip.split('/')[1]
        length = len(IPy.IP('127.0.0.0/{}'.format(num)))  # 计算网段的IP个数
        endiplists = list_of_groups(range(0, 256), length)  # 将整个C段按子网掩码划分成多个列表
        for endiplist in endiplists:  # 判断输入IP所在的子网
            if int(ip.split('/')[0].split('.')[-1].strip()) in endiplist:
                for endip in endiplist:
                    ip_list.append(
                        '.'.join(ip.split('/')[0].split('.')[:-1]) + '.{}'.format(endip))  # 以.为连接符，组合IP。
                break
    elif int(ip.split("/")[1]) >= 16:
        new_ip = ip.split(".")[0] + "." + ip.split(".")[1] + ".0.0/{}".format(ip.split("/")[1])
        ips = IPy.IP(new_ip)
        for i in ips:
            ip_list.append(str(i))
    else:
        new_ip = ip.split(".")[0] + ".0.0.0/{}".format(ip.split("/")[1])
        ips = IPy.IP(new_ip)
        for i in ips:
            ip_list.append(str(i))

elif re.match(r'^\d{0,3}.\d{0,3}.\d{0,3}.\d{0,3}$', ip) != None:
    ip_list.append(ip)

for i in ip_list:
    if http:
        asyncio.run(scan_ports(ip, ports, 2, data))
    elif pp:
        check_port_ping(ip, ports, data)
    elif syn:
        syn_scan(ip, ports, data)
    else:
        asyncio.run(scan_ports(ip, ports, 1, data))
    res.append(data)
    data = {'ip': '', 'port': [], 'protocol': [], 'service': []}


for i in range(len(res)):
    for j in range(len(res[i]['port'])):
        res[i]['protocol'].append(tcp_port_scan(res[i]['ip'], res[i]['port'][j]))
        res[i]['service'].append(get_service_name(res[i]['port'][j], res[i]['protocol'][j]))

if filename:
    if "txt" in filename:
        filename = filename.split(".")[0]
        Save_data_txt(s, filename)
    elif 'xlsx' in filename:
        filename = filename.split('.')[0]
        Save_Data_xlsx(res, filename)

print(res)