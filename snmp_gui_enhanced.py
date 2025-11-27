import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import asyncio
import threading
import pandas as pd
from pysnmp.hlapi.v3arch.asyncio import get_cmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
import warnings
warnings.filterwarnings('ignore')

class SNMPTesterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SNMP 团体字批量测试工具 - 增强版")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # 设置样式
        self.setup_styles()
        
        # 存储测试结果
        self.results = []
        self.total_tests = 0
        self.completed_tests = 0
        
        # 创建界面
        self.create_widgets()
        
    def setup_styles(self):
        """设置界面样式"""
        style = ttk.Style()
        style.theme_use('clam')  # 使用更现代的主题
        
        # 配置按钮样式
        style.configure('Accent.TButton', foreground='white', background='#4a90e2', padding=6)
        style.map('Accent.TButton', background=[('active', '#3a70c2')])
        
        # 配置标签样式
        style.configure('Title.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Section.TLabel', font=('Arial', 10, 'bold'))
        
    def create_widgets(self):
        """创建界面控件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="SNMP 团体字批量测试工具", style='Title.TLabel')
        title_label.pack(pady=(0, 15))
        
        # 输入区域框架
        input_frame = ttk.LabelFrame(main_frame, text="测试配置", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 15))
        
        # IP地址输入
        ip_frame = ttk.Frame(input_frame)
        ip_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(ip_frame, text="IP地址列表:", style='Section.TLabel').pack(anchor=tk.W)
        self.ip_text = tk.Text(ip_frame, height=4, font=('Consolas', 10))
        ip_scrollbar = ttk.Scrollbar(ip_frame, orient=tk.VERTICAL, command=self.ip_text.yview)
        self.ip_text.configure(yscrollcommand=ip_scrollbar.set)
        
        ip_text_frame = ttk.Frame(ip_frame)
        ip_text_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.ip_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ip_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Label(ip_frame, text="每行一个IP地址，例如: 192.168.1.1").pack(anchor=tk.W, pady=(5, 0))
        
        # 团体字输入
        community_frame = ttk.Frame(input_frame)
        community_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(community_frame, text="团体字列表:", style='Section.TLabel').pack(anchor=tk.W)
        self.community_text = tk.Text(community_frame, height=4, font=('Consolas', 10))
        community_scrollbar = ttk.Scrollbar(community_frame, orient=tk.VERTICAL, command=self.community_text.yview)
        self.community_text.configure(yscrollcommand=community_scrollbar.set)
        
        community_text_frame = ttk.Frame(community_frame)
        community_text_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.community_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        community_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Label(community_frame, text="每行一个团体字，例如: public").pack(anchor=tk.W, pady=(5, 0))
        
        # 配置选项
        config_frame = ttk.Frame(input_frame)
        config_frame.pack(fill=tk.X)
        
        # 端口配置
        port_frame = ttk.Frame(config_frame)
        port_frame.pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(port_frame, text="端口:").pack(anchor=tk.W)
        self.port_entry = ttk.Entry(port_frame, width=10)
        self.port_entry.insert(0, "161")
        self.port_entry.pack(pady=(5, 0))
        
        # 超时配置
        timeout_frame = ttk.Frame(config_frame)
        timeout_frame.pack(side=tk.LEFT)
        ttk.Label(timeout_frame, text="超时(秒):").pack(anchor=tk.W)
        self.timeout_entry = ttk.Entry(timeout_frame, width=10)
        self.timeout_entry.insert(0, "5")
        self.timeout_entry.pack(pady=(5, 0))
        
        # 并发数配置
        concurrency_frame = ttk.Frame(config_frame)
        concurrency_frame.pack(side=tk.LEFT, padx=(20, 0))
        ttk.Label(concurrency_frame, text="并发数:").pack(anchor=tk.W)
        self.concurrency_entry = ttk.Entry(concurrency_frame, width=10)
        self.concurrency_entry.insert(0, "10")
        self.concurrency_entry.pack(pady=(5, 0))
        
        # 控制按钮区域
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 开始测试按钮
        self.start_button = ttk.Button(control_frame, text="开始测试", style='Accent.TButton', command=self.start_test)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # 导出结果按钮
        self.export_button = ttk.Button(control_frame, text="导出结果", command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # 清空结果按钮
        self.clear_button = ttk.Button(control_frame, text="清空结果", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT)
        
        # 进度条区域
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.progress_label = ttk.Label(progress_frame, text="准备就绪")
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        self.progress_text = ttk.Label(progress_frame, text="")
        self.progress_text.pack(anchor=tk.E)
        
        # 输出区域框架
        output_frame = ttk.LabelFrame(main_frame, text="测试输出", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        # 输出文本框
        self.output_text = tk.Text(output_frame, font=('Consolas', 9))
        output_scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=output_scrollbar.set)
        
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 统计信息栏
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.stats_label = ttk.Label(stats_frame, text="总计: 0 | 成功: 0 | 失败: 0")
        self.stats_label.pack(side=tk.LEFT)
        
        # 添加一些示例数据以便测试
        self.add_sample_data()
        
    def add_sample_data(self):
        """添加示例数据"""
        sample_ips = """192.168.1.1
192.168.1.2
192.168.1.3
192.168.1.4
192.168.1.5
192.168.1.6
192.168.1.7
192.168.1.8
192.168.1.9
192.168.1.1"""
        
        sample_communities = """public
private"""
        
        self.ip_text.insert("1.0", sample_ips)
        self.community_text.insert("1.0", sample_communities)
        
    def update_progress(self):
        """更新进度条"""
        if self.total_tests > 0:
            progress_percent = (self.completed_tests / self.total_tests) * 100
            self.progress_bar['value'] = progress_percent
            self.progress_text.config(text=f"{self.completed_tests}/{self.total_tests}")
            
            # 更新状态文本
            if self.completed_tests < self.total_tests:
                self.progress_label.config(text=f"正在测试... ({progress_percent:.1f}%)")
            else:
                self.progress_label.config(text="测试完成")
                
        self.root.update_idletasks()
        
    def update_stats(self):
        """更新统计信息"""
        success_count = sum(1 for r in self.results if r['status'] == 'success')
        failed_count = len(self.results) - success_count
        self.stats_label.config(text=f"总计: {len(self.results)} | 成功: {success_count} | 失败: {failed_count}")
        
    def log_message(self, message):
        """在输出区域显示消息"""
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()
        
    def start_test(self):
        """开始测试"""
        # 获取输入数据
        ip_list = [line.strip() for line in self.ip_text.get("1.0", tk.END).strip().split("\n") if line.strip()]
        community_list = [line.strip() for line in self.community_text.get("1.0", tk.END).strip().split("\n") if line.strip()]
        
        if not ip_list or not community_list:
            messagebox.showwarning("输入错误", "请至少输入一个IP地址和一个团体字")
            return
            
        try:
            port = int(self.port_entry.get())
            timeout = int(self.timeout_entry.get())
            concurrency = int(self.concurrency_entry.get())
        except ValueError:
            messagebox.showerror("输入错误", "端口、超时时间和并发数必须是数字")
            return
            
        # 禁用开始按钮，启用导出按钮
        self.start_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        self.results = []
        self.completed_tests = 0
        self.total_tests = len(ip_list) * len(community_list)
        
        # 重置进度条
        self.progress_bar['value'] = 0
        self.progress_text.config(text=f"0/{self.total_tests}")
        self.progress_label.config(text="正在初始化...")
        self.update_stats()
        
        # 清空输出区域
        self.output_text.delete("1.0", tk.END)
        
        # 在新线程中运行测试
        test_thread = threading.Thread(
            target=self.run_async_test, 
            args=(ip_list, community_list, port, timeout, concurrency)
        )
        test_thread.daemon = True
        test_thread.start()
        
    def run_async_test(self, ip_list, community_list, port, timeout, concurrency):
        """在异步事件循环中运行测试"""
        try:
            # 创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.batch_test_snmp(ip_list, community_list, port, timeout, concurrency))
        except Exception as e:
            self.log_message(f"测试过程中出现错误: {str(e)}")
        finally:
            # 重新启用按钮
            self.root.after(0, self.enable_export_button)
            
    async def test_snmp_community(self, ip, community, port=161, timeout=5):
        """测试单个IP和团体字的组合"""
        try:
            # 创建传输目标
            transport_target = await UdpTransportTarget.create((ip, port), timeout)
            
            # 尝试获取系统描述符
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                SnmpEngine(),
                CommunityData(community),
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
            
            result = {
                'ip': ip,
                'port': port,
                'community': community,
                'status': 'failed',
                'error': '',
                'sys_descr': ''
            }
            
            if errorIndication:
                result['error'] = str(errorIndication)
            elif errorStatus:
                result['error'] = f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}'
            else:
                result['status'] = 'success'
                result['sys_descr'] = str(varBinds[0][1])
                
                # 输出成功信息，格式为: IP [团体字] 系统描述
                success_message = f"{ip} [{community}] {result['sys_descr']}"
                self.log_message(success_message)
                
            self.results.append(result)
            self.completed_tests += 1
            self.root.after(0, self.update_progress)
            self.root.after(0, self.update_stats)
            
            return result
        except Exception as e:
            error_result = {
                'ip': ip,
                'port': port,
                'community': community,
                'status': 'failed',
                'error': f'Exception: {str(e)}',
                'sys_descr': ''
            }
            self.results.append(error_result)
            self.completed_tests += 1
            self.log_message(f"测试 {ip} 使用团体字 '{community}' 时出现异常: {str(e)}")
            self.root.after(0, self.update_progress)
            self.root.after(0, self.update_stats)
            
            return error_result
            
    async def batch_test_snmp(self, ip_list, community_list, port=161, timeout=5, concurrency=10):
        """批量测试SNMP团体字"""
        self.log_message(f"开始批量测试，总共 {self.total_tests} 个测试项...")
        self.log_message(f"并发数: {concurrency}")
        self.root.after(0, self.update_progress)
        
        # 创建任务列表
        tasks = []
        for ip in ip_list:
            for community in community_list:
                task = self.test_snmp_community(ip, community, port, timeout)
                tasks.append(task)
                
        # 使用信号量控制并发数
        semaphore = asyncio.Semaphore(concurrency)
        
        async def bound_test(coro):
            async with semaphore:
                return await coro
                
        # 并发执行所有任务
        await asyncio.gather(*[bound_test(task) for task in tasks])
        
        self.log_message(f"测试完成，共获得 {len(self.results)} 个结果")
        self.root.after(0, self.update_progress)
        
    def enable_export_button(self):
        """启用导出按钮"""
        self.start_button.config(state=tk.NORMAL)
        if self.results:
            self.export_button.config(state=tk.NORMAL)
        
    def export_results(self):
        """导出测试结果"""
        if not self.results:
            messagebox.showinfo("无结果", "没有测试结果可以导出")
            return
            
        # 选择保存文件的位置
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel文件", "*.xlsx"), ("CSV文件", "*.csv"), ("所有文件", "*.*")],
            title="导出测试结果"
        )
        
        if not file_path:
            return
            
        try:
            # 创建DataFrame并保存
            df = pd.DataFrame(self.results)
            if file_path.endswith('.xlsx'):
                df.to_excel(file_path, index=False)
            else:
                df.to_csv(file_path, index=False)
                
            messagebox.showinfo("导出成功", f"结果已导出到: {file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出结果时出现错误: {str(e)}")
            
    def clear_results(self):
        """清空结果"""
        self.results = []
        self.completed_tests = 0
        self.total_tests = 0
        self.output_text.delete("1.0", tk.END)
        self.export_button.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0
        self.progress_text.config(text="")
        self.progress_label.config(text="准备就绪")
        self.update_stats()

def main():
    root = tk.Tk()
    app = SNMPTesterGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()