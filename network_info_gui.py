import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import datetime
import re
import sys
import ctypes
import threading
from queue import Queue, Empty

def _com_initialize(func):
    """COM初始化装饰器，确保线程安全的COM环境"""
    def wrapper(*args, **kwargs):
        import pythoncom
        pythoncom.CoInitialize()
        try:
            return func(*args, **kwargs)
        finally:
            pythoncom.CoUninitialize()
    return wrapper

class NetworkInfoApp:
    # 样式配置参数
    FONT_NAME = '微软雅黑'
    HEADER_FONT = (FONT_NAME, 10, 'bold')
    ROW_COLOR_EVEN = '#f8f9fa'
    ROW_COLOR_ODD = '#ffffff'

    def __init__(self, master: tk.Tk):
        """
        初始化GUI界面
        Args:
            master: tkinter根窗口对象
        """
        self.master = master
        try:
            # 设置主窗口
            master.title("Jild-网络配置工具")
            # 设置窗口图标
            try:
                icon = Image.open("Awei.ico")
                photo = ImageTk.PhotoImage(icon)
                master.iconphoto(True, photo)
            except Exception as e:
                print(f"图标加载失败: {str(e)}")
            master.geometry("800x460")
            master.resizable(True, True)  # 允许窗口调整大小

            # 配置表格样式
            style = ttk.Style()
            # 配置紧凑样式
            style.configure('Compact.Treeview', rowheight=20)
            style.configure('Treeview.Heading', 
                font=self.HEADER_FONT, 
                foreground='#2c3e50',
                padding=5)
            style.configure('Treeview', 
                rowheight=25,
                fieldbackground=self.ROW_COLOR_ODD,
                background=self.ROW_COLOR_EVEN)
            style.map('Treeview', background=[('selected', '#007bff')])
            
            # 创建表格
            self.tree = ttk.Treeview(master, columns=('IP地址', '子网掩码', '网关', 'DHCP模式'), 
                                    show='headings', height=8, style='Compact.Treeview')
            
            # 统一列配置
            col_config = {'anchor':'center', 'width':120}
            for col in self.tree['columns']:
                self.tree.heading(col, text=col, anchor='center')
                self.tree.column(col, **col_config)
            
            # 配置列属性
            self.tree.heading('DHCP模式', text='DHCP模式')
            self.tree.column('DHCP模式', width=100, anchor='center')
            self.tree.heading('#0', text='网卡名称', anchor='w')
            self.tree.column('#0', width=200, anchor='w', stretch=True)
            self.tree.heading('IP地址', text='IP地址')
            self.tree.heading('子网掩码', text='子网掩码')
            self.tree.heading('网关', text='网关')
            
            # 设置列宽
            self.tree.column('IP地址', width=150)
            self.tree.column('子网掩码', width=150)
            self.tree.column('网关', width=150)

            # 添加滚动条
            scrollbar = ttk.Scrollbar(master, orient=tk.VERTICAL, command=self.tree.yview)
            self.tree.configure(yscroll=scrollbar.set)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            # 紧凑布局
            self.tree.pack(fill='both', expand=True, padx=5, pady=2)

            # 添加日志显示区域
            self.log_frame = ttk.LabelFrame(master, text="系统日志")
            self.log_text = tk.Text(self.log_frame, height=6, wrap=tk.WORD, state=tk.DISABLED)
            self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
            self.log_frame.pack(fill='both', expand=True, padx=5, pady=5)

            # 获取数据按钮
            # 初始化状态栏组件
            self.status_bar = ttk.Frame(master)
            self.status_label = ttk.Label(self.status_bar, text="就绪", anchor=tk.W)
            self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Separator(self.status_bar).pack(side=tk.TOP, fill=tk.X)
            self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
            self.master.update_idletasks()
            
            self.refresh_btn = ttk.Button(master, text="刷新数据", command=lambda: self.load_data("刷新IP地址"))
            self.tree.bind('<Double-1>', self.show_adapter_details)
            self.refresh_btn.pack(pady=10)

            # 初始加载数据
            self.load_data("加载IP地址")
        except Exception as e:
            self.add_log("GUI初始化", False, str(e))

    def _configure_adapter(self, adapter):
        """
        执行网络适配器配置
        Args:
            adapter: WMI网络适配器对象
        """
        new_ip = '192.168.110.225'
        new_mask = '255.255.255.0'

        try:
            # 验证IP地址格式
            if not self.validate_ipv4(new_ip):
                raise ValueError("无效的IP地址格式")

            # 获取当前配置
            current_ips = list(adapter.IPAddress) if adapter.IPAddress else []
            current_masks = list(adapter.IPSubnet) if adapter.IPSubnet else []
            
            # 记录初始状态
            self.add_log("获取网络配置", True, f"当前IP: {', '.join(current_ips) if current_ips else '无'}")

            # 根据DHCP模式分别处理
            if adapter.DHCPEnabled:
                # DHCP模式处理
                # 获取有效IPv4配置
                valid_ips = [ip for ip in adapter.IPAddress if self.validate_ipv4(ip)]
                if not valid_ips:
                    raise ValueError("未找到有效IPv4地址")
                
                # 记录DHCP转静态操作
                self.add_log("DHCP转静态", True, f"将转换 {', '.join(valid_ips)}")
                
                # 先固定当前IP地址（将DHCP地址转为静态）
                valid_masks = current_masks[:len(valid_ips)]
                result = adapter.EnableStatic(IPAddress=valid_ips, SubnetMask=valid_masks)
                if result[0] != 0:  # 检查WMI调用结果
                    self.add_log("DHCP转静态", False, f"错误代码: {result[0]}")
                    raise Exception(f"设置静态IP失败，错误代码: {result[0]}")
                
                # 设置网关和DNS
                if adapter.DefaultIPGateway:
                    valid_gateways = [gw for gw in adapter.DefaultIPGateway if self.validate_ipv4(gw)]
                    if valid_gateways:
                        adapter.SetGateways(DefaultIPGateway=valid_gateways)
                        self.add_log("设置网关", True, f"网关: {', '.join(valid_gateways)}")
                
                dns_result = adapter.SetDNSServerSearchOrder(['8.8.8.8', '114.114.114.114'])
                if dns_result[0] == 0:
                    self.add_log("设置DNS", True, "DNS: 8.8.8.8, 114.114.114.114")
                else:
                    self.add_log("设置DNS", False, f"错误代码: {dns_result[0]}")
                
                # 添加新IP地址到高级TCP/IP设置
                if new_ip not in valid_ips:
                    # 创建新的IP和掩码列表，确保长度匹配
                    new_ip_list = valid_ips + [new_ip]
                    new_mask_list = valid_masks + [new_mask]
                    
                    self.add_log("添加新IP", True, f"尝试添加: {new_ip}/{new_mask}")
                    
                    # 重试机制确保IP地址添加成功
                    for attempt in range(3):
                        result = adapter.EnableStatic(IPAddress=new_ip_list, SubnetMask=new_mask_list)
                        if result[0] == 0:  # 成功
                            self.add_log("添加IP成功", True, f"第{attempt+1}次尝试")
                            break
                        else:
                            self.add_log("添加IP尝试", False, f"第{attempt+1}次尝试，错误代码: {result[0]}")
                            if attempt == 2:  # 最后一次尝试仍然失败
                                raise Exception(f"添加IP地址失败，错误代码: {result[0]}")
                else:
                    self.add_log("添加新IP", True, f"IP {new_ip} 已存在，无需添加")
            else:
                # 非DHCP模式直接添加新IP地址到高级TCP/IP设置
                if new_ip not in current_ips:
                    # 创建新的IP和掩码列表
                    new_ip_list = current_ips + [new_ip]
                    new_mask_list = current_masks + [new_mask]
                    
                    self.add_log("添加新IP", True, f"尝试添加: {new_ip}/{new_mask}")
                    
                    # 重试机制确保IP地址添加成功
                    for attempt in range(3):
                        result = adapter.EnableStatic(IPAddress=new_ip_list, SubnetMask=new_mask_list)
                        if result[0] == 0:  # 成功
                            self.add_log("添加IP成功", True, f"第{attempt+1}次尝试")
                            break
                        else:
                            self.add_log("添加IP尝试", False, f"第{attempt+1}次尝试，错误代码: {result[0]}")
                            if attempt == 2:  # 最后一次尝试仍然失败
                                raise Exception(f"添加IP地址失败，错误代码: {result[0]}")
                else:
                    self.add_log("添加新IP", True, f"IP {new_ip} 已存在，无需添加")

            # 确保在主线程执行GUI操作
            def show_success():
                # 确保进度窗口已关闭
                if hasattr(self, 'progress_popup') and self.progress_popup is not None and self.progress_popup.winfo_exists():
                    self.progress_popup.destroy()
                
                # 显示消息框并记录日志
                print("[DEBUG] 准备显示操作成功对话框")
                self.add_log("配置网络地址", True, "所有操作已完成")
                print("[DEBUG] 消息框已关闭")

                # 强制窗口刷新
                self.master.update_idletasks()
            
            # 检查新增地址是否生效 - 添加重试机制
            max_retries = 3
            for retry in range(max_retries):
                # 重新获取适配器的IP地址列表以验证配置是否成功
                updated_ips = list(adapter.IPAddress) if adapter.IPAddress else []
                new_ip_added = any(ip == new_ip for ip in updated_ips)
                
                if new_ip_added:
                    self.add_log("验证IP配置", True, f"已成功添加IP: {new_ip}")
                    self.master.after(0, lambda: [self.progress_popup.destroy(), setattr(self, 'progress_popup', None)] if hasattr(self, 'progress_popup') and self.progress_popup is not None and self.progress_popup.winfo_exists() else None)
                    self.master.after(0, show_success)  # 调用成功处理函数，输出日志
                    return  # 成功验证，直接返回
                
                if retry < max_retries - 1:
                    self.add_log("验证IP配置", False, f"第{retry+1}次验证未检测到新IP，将重试...")
                    import time
                    time.sleep(1)  # 等待1秒后重试
            
            # 如果所有重试都失败，记录警告并返回False表示验证失败
            self.add_log("验证IP配置", False, f"未检测到新IP: {new_ip}，配置可能未生效，请检查网络适配器设置或重启网卡")
            # 不再调用show_success，而是由调用者决定如何处理
            return False

        except Exception as e:
            error_msg = f"配置失败: {str(e)}"
            self.add_log("配置过程", False, error_msg)
            raise Exception(error_msg)

    def show_adapter_details(self, event):
        """
        显示选中网卡的详细信息
        """
        item = self.tree.selection()[0]
        adapter_name = self.tree.item(item, 'text')
        
        # 弹出配置确认对话框
        confirm = messagebox.askyesno("操作确认", 
            f"是否要为 [{adapter_name}] 配置IP地址？\n\n当前配置:\n{self.tree.item(item, 'values')}")
        
        if confirm:
            # 创建进度弹窗
            self.progress_popup = tk.Toplevel(self.master)
            self.progress_popup.title("配置执行中")
            tk.Label(self.progress_popup, text="正在配置网络参数，请勿关闭窗口").pack(padx=20, pady=10)
            self.progress_bar = ttk.Progressbar(self.progress_popup, mode='determinate', maximum=100, length=200)
            self.progress_bar.pack(padx=10, pady=5)
            
            def update_progress(step=0):
                if step <= 100:
                    # 检查进度弹窗是否存在
                    popup_exists = hasattr(self, 'progress_popup') and self.progress_popup is not None and self.progress_popup.winfo_exists()
                    progress_bar_exists = hasattr(self, 'progress_bar') and self.progress_bar is not None and self.progress_bar.winfo_exists() if popup_exists else False
                    if popup_exists and progress_bar_exists:
                        self.progress_bar['value'] = step
                        self.progress_popup.update_idletasks()
                    self.master.after(50, update_progress, step + 1)
                else:
                    if hasattr(self, 'progress_popup') and self.progress_popup is not None and self.progress_popup.winfo_exists():
                        self.progress_popup.destroy()
                        del self.progress_popup
            
            update_progress()
            # 双重保障关闭机制
            self.master.after(4500, lambda: [
                self.status_label.config(text="配置已完成，正在刷新数据..."),
                self.progress_popup.destroy(),
                delattr(self, 'progress_popup'),
                self.load_data()
            ] if hasattr(self, 'progress_popup') and self.progress_popup.winfo_exists() else None)
            
            self.master.after(5000, lambda: [
                self.progress_popup.destroy(),
                delattr(self, 'progress_popup'),
                self.load_data()
            ] if hasattr(self, 'progress_popup') and self.progress_popup.winfo_exists() else None)
            
            # 启动后台线程
            threading.Thread(target=self._async_configure_adapter, args=(adapter_name,), daemon=True).start()

    @_com_initialize
    def _async_configure_adapter(self, adapter_name):
        try:
            import wmi
            c = wmi.WMI()
            self.add_log("查找网络适配器", True, f"正在查找: {adapter_name}")
            adapters = c.Win32_NetworkAdapterConfiguration(Description=adapter_name)
            
            if adapters:
                success = False  # 标记配置是否成功
                try:
                    # 执行配置操作
                    self._configure_adapter(adapters[0])
                    
                    # 验证配置是否成功 - 检查IP是否已添加
                    new_ip = '192.168.110.225'
                    updated_ips = list(adapters[0].IPAddress) if adapters[0].IPAddress else []
                    if any(ip == new_ip for ip in updated_ips):
                        success = True
                        self.add_log("验证配置", True, f"IP {new_ip} 已成功添加")
                    else:
                        # 再次尝试检查IP
                        import time
                        time.sleep(1)  # 等待1秒后再次检查
                        # 重新获取适配器信息
                        adapters_refresh = c.Win32_NetworkAdapterConfiguration(Description=adapter_name)
                        if adapters_refresh:
                            updated_ips = list(adapters_refresh[0].IPAddress) if adapters_refresh[0].IPAddress else []
                            if any(ip == new_ip for ip in updated_ips):
                                success = True
                                self.add_log("验证配置", True, f"IP {new_ip} 已成功添加(延迟验证)")
                            else:
                                self.add_log("验证配置", False, f"未检测到IP {new_ip}，配置可能未生效")
                    
                    # 更新状态栏
                    self._update_status_bar('IP配置' + ('完成' if success else '可能未生效'))
                    
                    # 使用实际DNS服务器列表和IP配置
                    dns_servers = ['8.8.8.8', '114.114.114.114']
                    dns_info = '\n'.join([f'• DNS {i+1}: {dns}' for i, dns in enumerate(dns_servers)])
                    
                    # 根据验证结果显示不同消息
                    if success:
                        self.master.after(100, lambda: self._show_message(
                            "配置成功", 
                            f"网络配置已成功应用！\n\n新IP地址: 192.168.110.225/24\n{dns_info}", 
                            'info'
                        ))
                    else:
                        self.master.after(100, lambda: self._show_message(
                            "配置警告", 
                            f"配置操作已完成，但未检测到新IP地址。\n\n可能原因：\n1. 系统延迟更新\n2. IP地址冲突\n3. 网卡需要重启\n\n请检查网络适配器高级设置或重启网卡。", 
                            'warning'
                        ))
                    
                except Exception as e:
                    # 配置过程中的错误已在_configure_adapter中记录，这里只显示消息框
                    self.master.after(100, lambda: self._show_message(
                        "配置失败", 
                        f"网络配置过程中发生错误：\n{str(e)}\n\n请查看日志了解详细信息。", 
                        'error'
                    ))
            else:
                error_msg = f"找不到网络适配器: {adapter_name}"
                self.add_log("查找网络适配器", False, error_msg)
                self.master.after(100, lambda: self._show_message(
                    "适配器错误", 
                    error_msg, 
                    'error'
                ))
                
            # 关闭进度窗口
            self.master.after(0, lambda: self._safe_destroy('progress_popup'))
            self.master.after(0, lambda: self._safe_destroy('progress_bar'))
            
        except ImportError as e:
            error_msg = "缺少必要模块: wmi\n请通过命令安装: pip install wmi"
            self.add_log("加载网络模块", False, error_msg)
            self.master.after(100, lambda: self._show_message("模块错误", error_msg, 'error'))
        except Exception as e:
            error_msg = f"配置过程中发生错误：\n{str(e)}\n\n请检查：\n1. 网卡是否启用\n2. IP地址是否冲突\n3. 防火墙设置\n4. WMI服务状态"
            self.add_log("配置网络地址", False, error_msg)
            self.master.after(100, lambda: self._show_message("配置错误", error_msg, 'error'))
        finally:
            # 最终保障关闭机制
            self.master.after(10000, lambda: [
                self._safe_destroy('progress_popup'),
                self._safe_destroy('progress_bar')
            ] if hasattr(self, 'progress_popup') else None)

    def validate_ipv4(self, ip: str) -> bool:
        """
        验证IPv4地址格式有效性
        Args:
            ip: 待验证的IP地址字符串
        Returns:
            bool: 是否为有效IPv4地址
        """
        return bool(re.match(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$', ip))

    def load_data(self, operation_name="刷新IP地址"):
        self.current_operation = operation_name
        """
        加载网络适配器信息并更新表格
        """
        # 创建加载进度弹窗
        self.master.after(0, lambda: self._update_status_bar("正在加载网络信息..."))
        
        # 初始化队列并启动状态检查
        self.data_queue = Queue()
        self.status_checker = None
        threading.Thread(target=self._async_load_data, daemon=True).start()
        self._check_thread_status()

    def _update_status_bar(self, text):
        if hasattr(self, 'status_label'):
            self.master.after(0, lambda: self.status_label.config(text=text))
            self.master.update_idletasks()

    def _safe_destroy(self, attr_name):
        """安全销毁组件"""
        if hasattr(self, attr_name):
            widget = getattr(self, attr_name)
            if widget and hasattr(widget, 'winfo_exists') and widget.winfo_exists():
                widget.destroy()
            if hasattr(self, attr_name):  # 再次检查并删除属性
                delattr(self, attr_name)

    @_com_initialize
    def _async_load_data(self):
        try:
            import wmi
            c = wmi.WMI()
            adapters = list(c.Win32_NetworkAdapterConfiguration(IPEnabled=True))
            self.data_queue.put(adapters)
        except ImportError:
            error_msg = "缺少必要模块: wmi\n请通过命令安装: pip install wmi"
            self.add_log("加载网络模块", False, error_msg)
            self.data_queue.put([])
        except Exception as e:
            error_msg = f"获取网络信息失败:\n{str(e)}\n\n请确认：\n1. 系统WMI服务已启用\n2. 具有管理员权限"
            self._show_message("加载错误", error_msg, 'error')
            self.data_queue.put([])

    def _check_thread_status(self):
        try:
            adapters = self.data_queue.get(block=False)
            self._update_ui_with_data(adapters)
            self.status_checker = None
        except Empty:
            # 队列为空，继续检查
            self.status_checker = self.master.after(50, self._check_thread_status)
        except Exception as e:
            # 捕获其他异常并显示
            self.add_log("更新网络UI", False, str(e))
            self.status_checker = None

    def _show_message(self, title, message, msg_type='info'):
        """显示消息框
        Args:
            title: 消息框标题
            message: 消息内容
            msg_type: 消息类型 ('info', 'error', 'warning')
        """
        if msg_type == 'error':
            messagebox.showerror(title, message)
        elif msg_type == 'warning':
            messagebox.showwarning(title, message)
        else:
            messagebox.showinfo(title, message)

    def add_log(self, operation, success, error_msg=""):
        """添加带时间戳和状态的日志信息
        Args:
            operation: 操作名称
            success: 操作是否成功
            error_msg: 错误信息（可选）
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "成功" if success else "失败"
        log_msg = f"[{timestamp}] 操作: {operation}, 状态: {status}"
        if error_msg:
            log_msg += f", 日志信息: {error_msg}"
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_msg + "\n")
        self.log_text.see(tk.END)  # 滚动到最新消息
        self.log_text.config(state=tk.DISABLED)

    def _update_ui_with_data(self, adapters):
        # 清空现有数据
        for i in self.tree.get_children():
            self.tree.delete(i)

        # 检查适配器列表是否为空
        if not adapters:
            # 在表格中显示提示信息
            self.tree.insert('', 'end', text='无数据', values=('未找到', '启用IP的', '网络适配器', ''))
            self.add_log(self.current_operation, False, "未找到启用IP的网络适配器")
            return
        self.add_log(self.current_operation, True)

        for adapter in adapters:
            try:
                # 处理网关信息和IP过滤
                gateways = '--------'
                if adapter.DefaultIPGateway:
                    ipv4_gateways = [gw for gw in adapter.DefaultIPGateway if '.' in gw]
                    gateways = ','.join(ipv4_gateways) if ipv4_gateways else '--------'
                
                # 过滤IPv4地址
                ipv4_addresses = [ip for ip in (adapter.IPAddress or []) 
                                if self.validate_ipv4(ip)]
                subnets = adapter.IPSubnet[:len(ipv4_addresses)] if adapter.IPSubnet else []
                
                # 处理空数据显示
                ip_str = ', '.join(ipv4_addresses) or '--------'
                subnet_str = ', '.join(subnets) or '--------'
                desc = adapter.Description or '未知适配器'
                
                # 插入表格数据
                self.tree.insert('', 'end', 
                    text=desc,
                    values=(ip_str, subnet_str, gateways, '是' if adapter.DHCPEnabled else '否')
                )
            except Exception as e:
                # 单个适配器处理失败时显示错误但继续处理其他适配器
                self.add_log("处理网络适配器", False, str(e))

# 自检函数
def self_test():
    """
    运行自检：
    1. 检查wmi模块是否可用（仅Windows）
    2. 尝试获取至少一个网络适配器（仅Windows）
    3. 在非Windows环境中，检查网络模块
    自检失败时抛出异常
    """
    # 非Windows环境下的简化自检
    if sys.platform != 'win32':
        try:
            import socket
            # 获取主机名和IP地址作为基本网络功能测试
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return f"自检通过：非Windows环境，基本网络功能可用。主机名: {hostname}, IP: {ip_address}"
        except ImportError:
            raise Exception("缺少基本网络模块")
        except Exception as e:
            raise Exception(f"基本网络功能测试失败: {str(e)}")
    
    # Windows环境下的完整自检
    try:
        import wmi
        c = wmi.WMI()
        adapters = c.Win32_NetworkAdapterConfiguration(IPEnabled=True)
        if not list(adapters):
            raise Exception("未找到已启用的网络适配器")
        return "自检通过：组件正常"
    except ImportError:
        raise Exception("缺少必要模块: wmi。请通过命令安装: pip install wmi")
    except Exception as e:
        error_msg = f"自检失败：{str(e)}"
        raise Exception(error_msg)  # 抛出异常以便主程序捕获

def is_admin():
    """
    检查当前用户是否具有管理员权限
    在非Windows环境中始终返回True
    """
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        # 非Windows环境，假设已有足够权限
        return True

def show_error_message(title, message):
    """
    显示错误消息，跨平台兼容
    """
    if sys.platform == 'win32':
        try:
            ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
        except:
            print(f"{title}: {message}")
    else:
        # 非Windows环境使用标准输出
        print(f"\n{title}: {message}")

if __name__ == '__main__':
    try:
        # 检查是否为Windows环境
        is_windows = sys.platform == 'win32'
        
        # 在Windows环境下请求管理员权限
        if is_windows and not is_admin():
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
                sys.exit()
            except Exception as e:
                print(f"请求管理员权限失败: {str(e)}")
                print("尝试继续运行，但某些功能可能受限...")
        
        # 启动GUI
        root = tk.Tk()
        app = NetworkInfoApp(root)
        
        # 非Windows环境警告
        if not is_windows:
            app.add_log("环境检测", False, "检测到非Windows环境，网络配置功能将不可用")
            # 延迟显示警告消息，确保GUI已完全加载
            root.after(1000, lambda: app._show_message(
                "环境警告",
                "检测到非Windows环境，网络配置功能将不可用。\n\n此应用程序设计用于Windows系统，在当前环境中只能查看界面。",
                "warning"
            ))
        
        # 运行自检
        try:
            test_result = self_test()
            if is_windows:
                app.add_log("程序自检", True, "Windows环境组件正常")
            else:
                app.add_log("程序自检", True, "非Windows环境基本功能正常")
        except Exception as e:
            app.add_log("程序自检", False, str(e))
            # 在非Windows环境中，WMI相关自检失败是正常的
            if not is_windows and "wmi" in str(e).lower():
                app.add_log("环境检测", True, "WMI组件不可用，这在非Windows环境中是正常的")
        
        root.mainloop()
    except Exception as e:
        error_msg = f"无法启动应用程序：\n{str(e)}"
        # 确保错误信息能显示
        if 'app' in locals() and app is not None:
            app.add_log("应用程序启动", False, str(e))
        else:
            # 应用初始化失败时的后备错误显示
            show_error_message("程序启动失败", error_msg)
        sys.exit(1)