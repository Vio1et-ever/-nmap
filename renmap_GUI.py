import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
import asyncio
from renmap_logic import scan_ports, check_port_ping, Save_Data, tcp_port_scan, get_service_name, udp_port_scan

res = []


def run_scan():
    ip = ip_entry.get()
    ports = ports_entry.get()
    type_scan = type_var.get()
    file_ip = iplist_entry.get()
    file_name = file_entry.get()
    data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
    if ip:
        if type_scan == 4:
            check_port_ping(ip, ports, data)  # 进行ping扫描
            res.append(data)
            data = {'ip': '', 'port': [], 'protocol': [], 'service': []}
        else:
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

    for i in range(len(res)):
        for j in range(len(res[i]['port'])):
            res[i]['protocol'].append(tcp_port_scan(res[i]['ip'], res[i]['port'][j]))
            res[i]['service'].append(get_service_name(res[i]['port'][j], res[i]['protocol'][j]))
    if file_name:
        Save_Data(res, file_name)
    output_text.insert(tk.END, "ip\tport\tprotocol\tservice\tstate" + '\n')
    for i in range(len(res)):
        for j in range(len(res[i]['port'])):
            string = "{}\t{}\t{}\t{}\topen".format(res[i]['ip'], res[i]['port'][j], res[i]['protocol'][j], res[i]['service'][j])
            output_text.insert(tk.END, string + '\n')

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
tk.Radiobutton(app, text='ping扫描', variable=type_var, value=4).grid(row=4,column=2)

# 保存扫描数据
tk.Label(app, text="是否保存文件(默认为xlsx)").grid(row=5, column=0)
file_entry = tk.Entry(app)
file_entry.grid(row=5, column=1)

# 扫描按钮
scan_button = tk.Button(app, text="开始扫描", command=run_scan)
scan_button.grid(row=6, column=1)

# 输出结果的文本区域
output_text = scrolledtext.ScrolledText(app, width=70, height=20)
output_text.grid(row=7, column=0, columnspan=3)

app.mainloop()