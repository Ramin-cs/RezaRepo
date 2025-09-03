#!/usr/bin/env python3
"""
Router Configuration Decryptor GUI
رابط گرافیکی برای ابزار Decrypt کردن فایل‌های کانفیگ روتر
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
from router_config_decryptor import RouterConfigDecryptor
from advanced_router_decryptor import AdvancedRouterDecryptor

class RouterDecryptorGUI:
    """رابط گرافیکی برای ابزار decrypt"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("ابزار Decrypt کانفیگ روتر")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # ایجاد decryptor objects
        self.basic_decryptor = RouterConfigDecryptor()
        self.advanced_decryptor = AdvancedRouterDecryptor()
        
        self.setup_gui()
    
    def setup_gui(self):
        """راه‌اندازی رابط کاربری"""
        
        # عنوان
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill='x', pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame, 
            text="🔧 ابزار Decrypt کانفیگ روتر", 
            font=('Arial', 16, 'bold'),
            fg='white', 
            bg='#2c3e50'
        )
        title_label.pack(expand=True)
        
        # فریم اصلی
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # انتخاب فایل
        file_frame = tk.LabelFrame(main_frame, text="انتخاب فایل", font=('Arial', 10, 'bold'))
        file_frame.pack(fill='x', pady=(0, 10))
        
        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.file_path_var, width=60)
        file_entry.pack(side='left', padx=10, pady=10, fill='x', expand=True)
        
        browse_btn = tk.Button(
            file_frame, 
            text="انتخاب فایل", 
            command=self.browse_file,
            bg='#3498db',
            fg='white',
            font=('Arial', 9, 'bold')
        )
        browse_btn.pack(side='right', padx=10, pady=10)
        
        # گزینه‌های decrypt
        options_frame = tk.LabelFrame(main_frame, text="گزینه‌های Decrypt", font=('Arial', 10, 'bold'))
        options_frame.pack(fill='x', pady=(0, 10))
        
        # نوع روتر
        router_type_frame = tk.Frame(options_frame)
        router_type_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(router_type_frame, text="نوع روتر:", font=('Arial', 9)).pack(side='left')
        
        self.router_type = tk.StringVar(value="auto")
        router_combo = ttk.Combobox(
            router_type_frame, 
            textvariable=self.router_type,
            values=["auto", "cisco", "mikrotik", "juniper", "other"],
            state="readonly",
            width=15
        )
        router_combo.pack(side='left', padx=(10, 0))
        
        # پسورد Type 7
        password_frame = tk.Frame(options_frame)
        password_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(password_frame, text="پسورد Type 7:", font=('Arial', 9)).pack(side='left')
        
        self.type7_password = tk.StringVar()
        password_entry = tk.Entry(password_frame, textvariable=self.type7_password, width=30)
        password_entry.pack(side='left', padx=(10, 5))
        
        decrypt_pass_btn = tk.Button(
            password_frame,
            text="Decrypt پسورد",
            command=self.decrypt_password_only,
            bg='#e67e22',
            fg='white',
            font=('Arial', 8)
        )
        decrypt_pass_btn.pack(side='left', padx=5)
        
        # دکمه‌های اصلی
        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(fill='x', pady=10)
        
        decrypt_btn = tk.Button(
            buttons_frame,
            text="🔓 Decrypt فایل",
            command=self.decrypt_file,
            bg='#27ae60',
            fg='white',
            font=('Arial', 11, 'bold'),
            height=2
        )
        decrypt_btn.pack(side='left', padx=(0, 10), fill='x', expand=True)
        
        analyze_btn = tk.Button(
            buttons_frame,
            text="🔍 تجزیه پیشرفته",
            command=self.advanced_analyze,
            bg='#8e44ad',
            fg='white',
            font=('Arial', 11, 'bold'),
            height=2
        )
        analyze_btn.pack(side='left', padx=(0, 10), fill='x', expand=True)
        
        clear_btn = tk.Button(
            buttons_frame,
            text="🗑️ پاک کردن",
            command=self.clear_results,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 11, 'bold'),
            height=2
        )
        clear_btn.pack(side='left', fill='x', expand=True)
        
        # نتایج
        results_frame = tk.LabelFrame(main_frame, text="نتایج", font=('Arial', 10, 'bold'))
        results_frame.pack(fill='both', expand=True, pady=(10, 0))
        
        # ایجاد Notebook برای tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab نتایج اصلی
        self.results_tab = tk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="نتایج اصلی")
        
        self.results_text = scrolledtext.ScrolledText(
            self.results_tab,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#2c3e50',
            fg='#ecf0f1'
        )
        self.results_text.pack(fill='both', expand=True)
        
        # Tab محتوای فایل
        self.content_tab = tk.Frame(self.notebook)
        self.notebook.add(self.content_tab, text="محتوای فایل")
        
        self.content_text = scrolledtext.ScrolledText(
            self.content_tab,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg='#34495e',
            fg='#ecf0f1'
        )
        self.content_text.pack(fill='both', expand=True)
        
        # Tab گزارش
        self.report_tab = tk.Frame(self.notebook)
        self.notebook.add(self.report_tab, text="گزارش تفصیلی")
        
        self.report_text = scrolledtext.ScrolledText(
            self.report_tab,
            wrap=tk.WORD,
            font=('Tahoma', 9),
            bg='#ecf0f1',
            fg='#2c3e50'
        )
        self.report_text.pack(fill='both', expand=True)
        
        # نوار وضعیت
        self.status_var = tk.StringVar(value="آماده")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg='#bdc3c7',
            font=('Arial', 9)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def browse_file(self):
        """انتخاب فایل"""
        file_types = [
            ("تمام فایل‌ها", "*.*"),
            ("فایل‌های کانفیگ", "*.cfg;*.conf;*.txt"),
            ("فایل‌های Backup", "*.backup;*.bak"),
            ("فایل‌های متنی", "*.txt;*.log")
        ]
        
        filename = filedialog.askopenfilename(
            title="انتخاب فایل کانفیگ روتر",
            filetypes=file_types
        )
        
        if filename:
            self.file_path_var.set(filename)
    
    def decrypt_password_only(self):
        """فقط decrypt کردن پسورد Type 7"""
        password = self.type7_password.get().strip()
        if not password:
            messagebox.showwarning("هشدار", "لطفاً پسورد Type 7 را وارد کنید")
            return
        
        self.status_var.set("در حال decrypt کردن پسورد...")
        
        try:
            decrypted = self.basic_decryptor.decrypt_cisco_type7(password)
            
            result_text = f"پسورد رمزگذاری شده: {password}\n"
            result_text += f"پسورد رمزگشایی شده: {decrypted}\n"
            
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, result_text)
            
            self.status_var.set("پسورد با موفقیت decrypt شد")
            
        except Exception as e:
            messagebox.showerror("خطا", f"خطا در decrypt کردن پسورد: {e}")
            self.status_var.set("خطا در decrypt پسورد")
    
    def decrypt_file(self):
        """decrypt کردن فایل"""
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("هشدار", "لطفاً فایل را انتخاب کنید")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("خطا", "فایل وجود ندارد")
            return
        
        # اجرا در thread جداگانه
        threading.Thread(target=self._decrypt_file_thread, args=(file_path,), daemon=True).start()
    
    def _decrypt_file_thread(self, file_path):
        """thread برای decrypt کردن فایل"""
        self.root.after(0, lambda: self.status_var.set("در حال decrypt کردن فایل..."))
        
        try:
            result = self.basic_decryptor.decrypt_file(file_path)
            
            # نمایش نتایج در UI thread
            self.root.after(0, lambda: self._show_decrypt_results(result))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("خطا", f"خطا در decrypt: {e}"))
            self.root.after(0, lambda: self.status_var.set("خطا در decrypt"))
    
    def _show_decrypt_results(self, result):
        """نمایش نتایج decrypt"""
        # پاک کردن نتایج قبلی
        self.results_text.delete(1.0, tk.END)
        self.content_text.delete(1.0, tk.END)
        
        # نمایش نتایج اصلی
        results_output = "نتایج Decrypt:\n" + "=" * 40 + "\n"
        results_output += f"نوع فایل: {result.get('file_type', 'نامشخص')}\n"
        results_output += f"وضعیت: {'موفق' if result.get('success') else 'ناموفق'}\n\n"
        
        if 'error' in result:
            results_output += f"خطا: {result['error']}\n"
        
        if 'passwords' in result and result['passwords']:
            results_output += "🔑 پسوردهای یافت شده:\n"
            for pwd in result['passwords']:
                results_output += f"  • {pwd['decrypted']} (از: {pwd['encrypted']})\n"
            results_output += "\n"
        
        if 'interfaces' in result and result['interfaces']:
            results_output += f"🌐 Interfaces ({len(result['interfaces'])} عدد):\n"
            for interface in result['interfaces'][:5]:
                results_output += f"  • {interface}\n"
            results_output += "\n"
        
        self.results_text.insert(1.0, results_output)
        
        # نمایش محتوای فایل
        if 'content' in result:
            self.content_text.insert(1.0, result['content'])
        
        self.status_var.set("فایل با موفقیت پردازش شد")
    
    def advanced_analyze(self):
        """تجزیه پیشرفته فایل"""
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("هشدار", "لطفاً فایل را انتخاب کنید")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("خطا", "فایل وجود ندارد")
            return
        
        # اجرا در thread جداگانه
        threading.Thread(target=self._advanced_analyze_thread, args=(file_path,), daemon=True).start()
    
    def _advanced_analyze_thread(self, file_path):
        """thread برای تجزیه پیشرفته"""
        self.root.after(0, lambda: self.status_var.set("در حال تجزیه پیشرفته..."))
        
        try:
            result = self.advanced_decryptor.analyze_file(file_path)
            
            # نمایش نتایج در UI thread
            self.root.after(0, lambda: self._show_advanced_results(result))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("خطا", f"خطا در تجزیه: {e}"))
            self.root.after(0, lambda: self.status_var.set("خطا در تجزیه"))
    
    def _show_advanced_results(self, result):
        """نمایش نتایج تجزیه پیشرفته"""
        # پاک کردن tab گزارش
        self.report_text.delete(1.0, tk.END)
        
        # تولید گزارش
        report = []
        report.append("🔧 گزارش تجزیه پیشرفته")
        report.append("=" * 40)
        
        file_info = result.get('file_info', {})
        report.append(f"📁 فایل: {os.path.basename(file_info.get('path', ''))}")
        report.append(f"📊 اندازه: {file_info.get('size', 0)} بایت")
        report.append(f"🔐 روش رمزنگاری: {result.get('encryption_method', 'نامشخص')}")
        report.append(f"✅ وضعیت: {'موفق' if result.get('success') else 'ناموفق'}")
        
        if 'error' in result:
            report.append(f"❌ خطا: {result['error']}")
        
        # اطلاعات شبکه
        network_info = result.get('network_info', {})
        if network_info:
            report.append("\n🌐 اطلاعات شبکه:")
            report.append("-" * 25)
            
            if network_info.get('hostname'):
                report.append(f"🏷️ نام میزبان: {network_info['hostname']}")
            
            if network_info.get('ip_addresses'):
                report.append(f"🔢 آدرس‌های IP ({len(network_info['ip_addresses'])}):")
                for ip in network_info['ip_addresses'][:10]:
                    report.append(f"   • {ip}")
            
            if network_info.get('users'):
                report.append(f"👤 کاربران ({len(network_info['users'])}):")
                for user in network_info['users'][:5]:
                    report.append(f"   • {user}")
        
        # نتایج brute force
        if 'brute_force_results' in result:
            report.append("\n🔓 نتایج Brute Force:")
            report.append("-" * 25)
            for br_result in result['brute_force_results']:
                report.append(f"روش: {br_result['method']}, پسورد: {br_result['password']}")
        
        report_text = '\n'.join(report)
        self.report_text.insert(1.0, report_text)
        
        # نمایش محتوای decrypt شده
        if 'decrypted_data' in result:
            self.content_text.delete(1.0, tk.END)
            self.content_text.insert(1.0, result['decrypted_data'])
        elif 'text_content' in result:
            self.content_text.delete(1.0, tk.END)
            self.content_text.insert(1.0, result['text_content'])
        
        # تغییر به tab گزارش
        self.notebook.select(self.report_tab)
        
        self.status_var.set("تجزیه پیشرفته کامل شد")
    
    def clear_results(self):
        """پاک کردن همه نتایج"""
        self.results_text.delete(1.0, tk.END)
        self.content_text.delete(1.0, tk.END)
        self.report_text.delete(1.0, tk.END)
        self.file_path_var.set("")
        self.type7_password.set("")
        self.status_var.set("آماده")
    
    def save_results(self):
        """ذخیره نتایج"""
        content = self.content_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("هشدار", "محتوایی برای ذخیره وجود ندارد")
            return
        
        filename = filedialog.asksaveasfilename(
            title="ذخیره نتایج",
            defaultextension=".txt",
            filetypes=[("فایل متنی", "*.txt"), ("تمام فایل‌ها", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("موفقیت", f"نتایج در {filename} ذخیره شد")
            except Exception as e:
                messagebox.showerror("خطا", f"خطا در ذخیره: {e}")


def main():
    """اجرای برنامه"""
    root = tk.Tk()
    
    # تنظیم font فارسی
    try:
        root.option_add('*Font', 'Tahoma 9')
    except:
        pass
    
    app = RouterDecryptorGUI(root)
    
    # منوی راست کلیک برای ذخیره
    def show_context_menu(event):
        context_menu = tk.Menu(root, tearoff=0)
        context_menu.add_command(label="ذخیره نتایج", command=app.save_results)
        context_menu.add_separator()
        context_menu.add_command(label="کپی", command=lambda: event.widget.event_generate("<<Copy>>"))
        context_menu.add_command(label="انتخاب همه", command=lambda: event.widget.event_generate("<<SelectAll>>"))
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    app.results_text.bind("<Button-3>", show_context_menu)
    app.content_text.bind("<Button-3>", show_context_menu)
    app.report_text.bind("<Button-3>", show_context_menu)
    
    root.mainloop()


if __name__ == "__main__":
    main()