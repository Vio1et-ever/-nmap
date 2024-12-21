import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
import asyncio
from nmap_logic import *
import nmap_logic


res = []
s = []

def run_scan():
    global res
    global s
    ip = ip_entry.get()
    ports = ports_entry.get()
    type_scan = type_var.get()
    file_ip = iplist_entry.get()
    data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
    res = []
    s = []
    newIplist = []
    if "/" in ip:
        if int(ip.split("/")[1]) >= 24:
            num = ip.split('/')[1]
            length = len(IPy.IP('127.0.0.0/{}'.format(num)))  # 计算网段的IP个数
            endiplists = list_of_groups(range(0, 256), length)  # 将整个C段按子网掩码划分成多个列表
            for endiplist in endiplists:  # 判断输入IP所在的子网
                if int(ip.split('/')[0].split('.')[-1].strip()) in endiplist:
                    for endip in endiplist:
                        newIplist.append(
                            '.'.join(ip.split('/')[0].split('.')[:-1]) + '.{}'.format(endip))  # 以.为连接符，组合IP。
                    break
        elif int(ip.split("/")[1]) >= 16:
            new_ip = ip.split(".")[0] + "." + ip.split(".")[1] + ".0.0/{}".format(ip.split("/")[1])
            ips = IPy.IP(new_ip)
            for i in ips:
                newIplist.append(str(i))
        else:
            new_ip = ip.split(".")[0] + ".0.0.0/{}".format(ip.split("/")[1])
            ips = IPy.IP(new_ip)
            for i in ips:
                newIplist.append(str(i))
    elif re.match(r'^\d{0,3}.\d{0,3}.\d{0,3}.\d{0,3}$', ip) != None:
        newIplist.append(ip)

    if ip and ports:
        if type_scan == 4:
            for ip in newIplist:
                check_port_ping(ip, ports, data)  # 进行ping扫描
                res.append(data)
                data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
        else:
            for ip in newIplist:
                asyncio.run(scan_ports(ip, ports, 1, data))  # type = 1 进行端口扫描 type = 2 进行http连接
                res.append(data)
                data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
    if file_ip:
        ip_list = []
        # 获取IP地址
        with open(file_ip, 'r') as f:
            line = f.readline()
            while line:
                if "\n" in line:
                    ip_list.append(line.split("\n")[0])
                else:
                    ip_list.append(line)
                line = f.readline()
        for i in ip_list:
            if type_scan == 4:
                check_port_ping(i, ports, data)  # 进行ping扫描
                res.append(data)
                data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
            else:
                asyncio.run(scan_ports(i, ports, 1, data))  # type = 1 进行端口扫描 type = 2 进行http连接
                res.append(data)
                data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
    if type_scan == 2:
        for i in range(len(res)):
            for port in res[i]['port']:
                asyncio.run(scan_ports(res[i]['ip'], port, 2, data))
    elif type_scan == 3:
        for i in range(len(res)):
            for j in range(len(res[i]['port'])):
                res[i]['protocol'][j] = udp_port_scan(res[i]['ip'], res[i]['port'][j])
    elif type_scan == 5:
        get_survive_ip(ip)
        s = nmap_logic.string
        for i in s:
            output_text.insert(tk.END, "ip {} is alive\n".format(i))
        return 0
    elif type_scan == 6:
        for i in newIplist:
            output_text.insert(tk.END, i)
    for i in range(len(res)):
        for j in range(len(res[i]['port'])):
            res[i]['protocol'].append(tcp_port_scan(res[i]['ip'], res[i]['port'][j]))
            res[i]['service'].append(get_service_name(res[i]['port'][j], res[i]['protocol'][j]))
    output_text.insert(tk.END, "ip\tport\tprotocol\tservice\tstate" + '\n')
    for i in range(len(res)):
        for j in range(len(res[i]['port'])):
            string = "{}\t{}\t{}\t{}\topen".format(res[i]['ip'], res[i]['port'][j], res[i]['protocol'][j],
                                                   res[i]['service'][j])
            output_text.insert(tk.END, string + '\n')

def save():
    file_type = file_var.get()
    filename = file_entry.get()
    if file_type == 1:
        Save_Data_xlsx(res, filename)
    elif file_type == 2:
        Save_data_txt(s, filename)


def select_iplist():
    filename = filedialog.askopenfilename()
    iplist_entry.delete(0, tk.END)
    iplist_entry.insert(0, filename)


app = tk.Tk()
app.title("端口扫描工具")

# 设置IP地址输入
tk.Label(app, text="IP地址:").grid(row=0, column=0)
ip_entry = tk.Entry(app)
ip_entry.grid(row=0, column=1)

tk.Label(app, text="IP文件:").grid(row=1, column=0)
iplist_entry = tk.Entry(app)
iplist_entry.grid(row=1, column=1)
iplist_button = tk.Button(app, text="Browse...", command=select_iplist)
iplist_button.grid(row=1, column=2)

# 设置端口范围输入
tk.Label(app, text="端口范围 (例如 1-1024):").grid(row=2, column=0)
ports_entry = tk.Entry(app)
ports_entry.grid(row=2, column=1)

# 设置扫描类型选择
tk.Label(app, text="选择扫描类型:").grid(row=3, column=0)
type_var = tk.IntVar()
tk.Radiobutton(app, text="常规扫描", variable=type_var, value=1).grid(row=3, column=1)
tk.Radiobutton(app, text="HTTP扫描", variable=type_var, value=2).grid(row=3, column=2)
tk.Radiobutton(app, text="UDP扫描", variable=type_var, value=3).grid(row=4, column=1)
tk.Radiobutton(app, text='ping扫描', variable=type_var, value=4).grid(row=4, column=2)
tk.Radiobutton(app, text='扫描主机', variable=type_var, value=5).grid(row=5, column=1)
tk.Radiobutton(app, text='获取主机', variable=type_var, value=6).grid(row=5, column=2)


# 保存扫描数据
file_var = tk.IntVar()
tk.Label(app, text="是否保存文件").grid(row=6, column=0)
file_entry = tk.Entry(app)
file_entry.grid(row=6, column=1)
tk.Radiobutton(app, text='xlsx', variable=file_var, value=1).grid(row=7, column=1)
tk.Radiobutton(app, text='txt', variable=file_var, value=2).grid(row=7, column=2)
save_button = tk.Button(app, text="保存数据", command=save)
save_button.grid(row=6, column=2)

# 扫描按钮
scan_button = tk.Button(app, text="开始扫描", command=run_scan)
scan_button.grid(row=8, column=1)

# 输出结果的文本区域
output_text = scrolledtext.ScrolledText(app, width=70, height=20)
output_text.grid(row=9, column=0, columnspan=3)

app.mainloop()
