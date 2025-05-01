import random
import re
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter.ttk import *
import xml.etree.ElementTree as ET
import string




#--------------变量控制区-----------------

version = 1.01  # 版本控制
debug = False   # 日志输出开关

#-----------------------------------------



def logger(content):
    if debug == True:
        print(content)
    else:
        pass

def read_file(file):
    tree = ET.parse(file)
    root = tree.getroot()
    return root

def save_file(root, file):
    xml_str = ET.tostring(root, encoding='utf-8')
    # 写入文件
    with open(file, 'wb') as f:
        f.write('<?xml version ="1.0" encoding ="UTF-8" ?>\n'.encode() + xml_str)
    return 0

def is_array(variable):
    return isinstance(variable, list)

class WinGUI(Tk):
    def __init__(self):
        super().__init__()
        self.__win()
        self.tk_table_m9v8rfji = self.__tk_table_m9v8rfji(self)

    def __win(self):
        self.title("Hacknet存档读取工具_v" + str(version))
        width = 717
        height = 425
        screenwidth = self.winfo_screenwidth()
        screenheight = self.winfo_screenheight()
        geometry = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.geometry(geometry)
        self.minsize(width=width, height=height)

    def scrollbar_autohide(self, vbar, hbar, widget):
        def show():
            if vbar: vbar.lift(widget)
            if hbar: hbar.lift(widget)
        def hide():
            if vbar: vbar.lower(widget)
            if hbar: hbar.lower(widget)
        hide()
        widget.bind("<Enter>", lambda e: show())
        if vbar: vbar.bind("<Enter>", lambda e: show())
        if vbar: vbar.bind("<Leave>", lambda e: hide())
        if hbar: hbar.bind("<Enter>", lambda e: show())
        if hbar: hbar.bind("<Leave>", lambda e: hide())
        widget.bind("<Leave>", lambda e: hide())

    def v_scrollbar(self, vbar, widget, x, y, w, h, pw, ph):
        widget.configure(yscrollcommand=vbar.set)
        vbar.config(command=widget.yview)
        vbar.place(relx=(w + x) / pw, rely=y / ph, relheight=h / ph, anchor='ne')

    def h_scrollbar(self, hbar, widget, x, y, w, h, pw, ph):
        widget.configure(xscrollcommand=hbar.set)
        hbar.config(command=widget.xview)
        hbar.place(relx=x / pw, rely=(y + h) / ph, relwidth=w / pw, anchor='sw')

    def create_bar(self, master, widget, is_vbar, is_hbar, x, y, w, h, pw, ph):
        vbar, hbar = None, None
        if is_vbar:
            vbar = Scrollbar(master)
            self.v_scrollbar(vbar, widget, x, y, w, h, pw, ph)
        if is_hbar:
            hbar = Scrollbar(master, orient="horizontal")
            self.h_scrollbar(hbar, widget, x, y, w, h, pw, ph)
        self.scrollbar_autohide(vbar, hbar, widget)

    def __tk_table_m9v8rfji(self, parent):
        columns = {"IP": 101, "节点名称": 134, "解锁状态": 61, "管理员": 61, "管理员密码": 134, "防火墙密码": 101, "开放端口": 101,"追踪时间":71,"破解端口数": 81}
        tk_table = Treeview(parent, show="headings", columns=list(columns),)
        for text, width in columns.items():
            tk_table.heading(text, text=text, anchor='center')
            tk_table.column(text, anchor='center', width=width, stretch=False)
        tk_table.place(relx=0.0293, rely=0.0471, relwidth=0.9414, relheight=0.9082)
        self.create_bar(parent, tk_table, True, True, 21, 20, 675, 386, 717, 425)
        return tk_table

class Win(WinGUI):
    def __init__(self, controller):
        self.ctl = controller
        super().__init__()
        self.__event_bind()
        self.__style_config()
        self.config(menu=self.create_menu())
        self.ctl.init(self)

    def create_menu(self):
        menu = Menu(self, tearoff=False)
        menu.add_cascade(label="文件", menu=self.menu_m9v95o42(menu))
        menu.add_cascade(label="功能", menu=self.menu_m9v8tcoh(menu))
        return menu

    def __event_bind(self):
        self.protocol("WM_DELETE_WINDOW", self.ctl.quitApp)
        self.tk_table_m9v8rfji.bind('<Double-1>', self.ctl.edit_row)

    def menu_m9v8tcoh(self, parent):
        menu = Menu(parent, tearoff=False)
        menu.add_command(label="一键获取全节点管理员权限", command=self.ctl.getAllComputerAdmin)
        menu.add_command(label="一键解锁全节点", command=self.ctl.unlockAllComputer)
        menu.add_command(label="一键坚不可摧", command=self.ctl.makeMyComputerUnbreakable)
        return menu

    def menu_m9v95o42(self, parent):
        menu = Menu(parent, tearoff=False)
        menu.add_command(label="打开存档", command=self.ctl.openFile)
        menu.add_command(label="覆盖保存", command=self.ctl.saveFile)
        menu.add_command(label="另存为", command=self.ctl.saveAnotherFile)
        menu.add_command(label="退出", command=self.ctl.quitApp)
        return menu

    def __style_config(self):
        pass

class Controller:
    ui = None
    xml_root = None
    computer_num = 0
    computer_unlock_list = None

    def __init__(self):
        pass

    def init(self, ui):
        self.ui = ui

    def insert_firewall_after_links(self, parent_element, firewall_pass):
        # 查找所有子元素
        children = list(parent_element)

        # 定位 <links> 的索引
        links_index = None
        for idx, child in enumerate(children):
            if child.tag == 'links':
                links_index = idx
                break

        # 如果找到 <links> 且后面不是 <portsOpen>
        if links_index is not None and links_index + 1 < len(children):
            next_sibling = children[links_index + 1]
            if next_sibling.tag == 'portsOpen':
                # 创建防火墙元素
                firewall = ET.SubElement(parent_element, 'firewall', {
                    'additionalDelay': '0',
                    'complexity': '0',
                    'solution': firewall_pass  # 可改为 random_string() 生成随机解
                })
                # 插入到 <links> 之后
                parent_element.insert(links_index + 1, firewall)
        elif links_index is not None:
            # 如果 <links> 是最后一个元素
            firewall = ET.SubElement(parent_element, 'firewall', {
                'additionalDelay': '0',
                'complexity': '0',
                'solution': firewall_pass
            })
            parent_element.insert(links_index + 1, firewall)

    def showComputer(self):
        # 获取玩家名称
        hacknet_save = self.xml_root
        if hacknet_save is None:
            messagebox.showerror("错误", "存档格式不正确，找不到HacknetSave节点")
            logger("[存档加载]检测到坏档！问题：找不到HacknetSave节点")
            return
            
        game_user = hacknet_save.get('Username')
        if not game_user:
            game_user = "未知玩家"
            
        self.ui.title("Hacknet存档读取工具_v" + str(version) + " - 当前玩家：" + str(game_user))
        logger("[存档加载]当前存档玩家：" + str(game_user))

        # 获取解锁节点情况
        self.computer_unlock_list = list(map(int, self.xml_root.find('NetworkMap').find("visible").text.split()))
        logger("[存档加载]当前解锁节点列表:"+ str(self.computer_unlock_list))
            
        # 清空表格
        for item in self.ui.tk_table_m9v8rfji.get_children():
            self.ui.tk_table_m9v8rfji.delete(item)

        self.computer_num = 0
        # 遍历所有计算机节点
        for computer in self.xml_root.findall('.//computer'):
            computer_ip = computer.get('ip')
            computer_name = computer.get('name')
            
            # 获取安全信息
            security = computer.find('security')
            computer_trace_time = security.get('traceTime') if security is not None else ""
            computer_port_to_crack = security.get('portsToCrack') if security is not None else ""
            computer_admin_ip = security.get('adminIP') if security is not None else ""
            
            # 获取端口信息
            computer_ports = computer.find('portsOpen').text if computer.find('portsOpen') is not None else ""
            
            # 获取防火墙信息
            firewall = computer.find('firewall')
            computer_firewall_solve = firewall.get('solution') if firewall is not None else ""
            
            # 获取用户信息
            admin_pass = ""
            users = computer.find('users')
            if users is not None:
                for user in users.findall('user'):
                    if user.get('name') == 'admin':
                        admin_pass = user.get('pass')
                        break
            
            # 判断是否是管理员
            if computer_admin_ip == self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip'):
                isAdmin = "是"
            else:
                isAdmin = "否"

            if self.computer_num in self.computer_unlock_list:
                isUnlocked = "是"
            else:
                isUnlocked = "否"
            
            data = [computer_ip, computer_name, isUnlocked, isAdmin, admin_pass, computer_firewall_solve, computer_ports, computer_trace_time, computer_port_to_crack]
            self.ui.tk_table_m9v8rfji.insert('', END, values=data)
            self.computer_num=self.computer_num+1
        logger("[存档加载]存档加载完成")
            
    def openFile(self):
        file_types = [('存档文件', '*.xml')]
        self.xml_file = filedialog.askopenfilename(title='打开存档', filetypes=file_types)
        if not self.xml_file:
            return
        
        try:
            self.xml_root = read_file(self.xml_file)
        except Exception as e:
            messagebox.showinfo(message="存档不合法！请检查存档: " + str(e))
            logger("[打开存档]存档不合法！请检查存档:", e)
            return

        logger("[打开存档]开始加载存档")
        self.showComputer()

    def saveFile(self):
        if self.xml_root is None:
            messagebox.showinfo(message="老弟，你没打开就保存啊？")
            logger("[覆盖保存]未打开存档就保存")
            return
            
        try:
            response = messagebox.askyesno("确认", "你确定要覆盖保存存档吗？此行为不可逆")
            if response:
                save_file(self.xml_root, self.xml_file)
                messagebox.showinfo(message="存档保存成功！")
                logger("[覆盖保存]保存成功")
        except Exception as e:
            messagebox.showinfo(message=f"保存失败: {str(e)}")
            logger("保存失败: "+str(e))
            logger("[覆盖保存]保存失败："+str(e))

    def saveAnotherFile(self):
        if self.xml_root is None:
            messagebox.showinfo(message="老弟，你没打开就保存啊？")
            logger("[另存为]未打开存档就保存")
            return
            
        try:
            file_types = [('存档文件', '*.xml')]
            r = filedialog.asksaveasfilename(title='保存存档到', filetypes=file_types)
            if r:
                save_file(self.xml_root, r)
                logger("[另存为]存档保存成功")
                messagebox.showinfo(message="存档保存成功！")
        except Exception as e:
            messagebox.showinfo(message=f"保存失败: {str(e)}")
            logger("[另存为]保存失败："+str(e))

    def quitApp(self):
        response = messagebox.askyesno("提示", "确定关闭软件？")
        if response:
            logger("[退出程序]用户离开")
            exit()
        else:
            pass

    def unlockAllComputer(self):
        if self.xml_root is None:
            messagebox.showinfo(message="老弟，你存档呢？")
            logger("[全节点解锁]未打开存档就使用功能")
            return
            
        try:
            computer_unlock_list = ' '.join(str(i) for i in range(self.computer_num))
            self.xml_root.find('NetworkMap').find("visible").text = computer_unlock_list
            messagebox.showinfo(message="全节点解锁获取完成！")
            logger("[全节点解锁]全节点解锁获取完成，刷新存档")
            self.showComputer()
        except Exception as e:
            messagebox.showinfo(message=f"操作失败: {str(e)}")
            logger("[全节点解锁]操作失败："+str(e))
 
    def getAllComputerAdmin(self):
        if self.xml_root is None:
            messagebox.showinfo(message="老弟，你存档呢？")
            logger("[全管理员]未打开存档就使用功能")
            return
            
        try:
            gamer_ip = self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip')
            for computer in self.xml_root.findall('.//computer'):
                security = computer.find('security')
                if security is not None:
                    security.set('adminIP', gamer_ip)
                else:
                    logger("[全管理员]检测到坏档！问题：节点"+computer.get('name')+"的安全数据缺失！")
                    return
                    #security = ET.SubElement(computer, 'security')
                    #security.set('adminIP', gamer_ip)
                    #security.set('traceTime', '0')
                    #security.set('portsToCrack', '0')

                users = computer.find('users')
                if users is not None:
                    for user in users.findall('user'):
                        user.set('known',"True")
            
            messagebox.showinfo(message="管理员权限获取完成！")
            logger("[全管理员]管理员权限获取完成，刷新存档")
            self.showComputer()
        except Exception as e:
            messagebox.showinfo(message=f"操作失败: {str(e)}")
            logger("[全管理员]操作失败: "+str(e))

    def makeMyComputerUnbreakable(self):
        if self.xml_root is None:
            messagebox.showinfo(message="老弟，你存档呢？")
            logger("[无懈可击]未打开存档就使用功能")
            return
            
        try:
            # 获取玩家计算机
            player_computer = self.xml_root.find('.//NetworkMap/network/computer[1]')
            
            # 修改安全设置
            security = player_computer.find('security')
            if security is None:
                security = ET.SubElement(player_computer, 'security')
            logger("[无懈可击]设置EnTech防护")
            security.set('portsToCrack', '9999998')
            logger("[无懈可击]设置瞬间追踪")
            security.set('traceTime', '1')
            security.set('proxyTime', '9999998')
            
            # 修改防火墙设置
            firewall = player_computer.find('firewall')
            logger("[无懈可击]设置高强度防火墙密码")
            if firewall is None:
                self.insert_firewall_after_links(player_computer, ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12)))
            else:
                firewall.set('solution', ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12)))
            
            # 设置开放端口
            ports_open = player_computer.find('portsOpen')
            if ports_open is None:
                # ports_open = ET.SubElement(player_computer, 'portsOpen')
                logger("[无懈可击]检测到坏档！问题：玩家电脑的端口数据缺失")
                return
            logger("[无懈可击]设置全端口")
            ports_open.text = "80 25 21 22 1433 3659 104"
            
            messagebox.showinfo(message="你的电脑坚不可摧！[滑稽]")
            self.showComputer()
        except Exception as e:
            messagebox.showinfo(message=f"操作失败: {str(e)}")
            logger("[无懈可击]操作失败: "+str(e))
    
    def edit_row(self, event):
        tree = self.ui.tk_table_m9v8rfji
        item = tree.selection()[0]  # 获取选中的行
        
        
        # 创建编辑窗口
        window = Toplevel(self.ui)
        window.title("编辑行")
        
        # 获取当前行的值
        values = tree.item(item, 'values')
        
        # 创建输入框
        entries = []
        for i, (column, value) in enumerate(zip(tree["columns"], values)):
            label = Label(window, text=column)
            label.grid(row=i, column=0, sticky="e")
            
            entry = Entry(window)
            entry.insert(0, value)
            entry.grid(row=i, column=1, sticky="w")
            entries.append(entry)
            
        def apply_edit():
            global xml_root
            new_values = [entry.get() for entry in entries]
            tree.item(item, values=new_values)
            logger("[修改数据]当前选中项目编号"+item)
            
            # 找到对应的计算机节点
            computer = self.xml_root.find(f'.//computer[@ip="{new_values[0]}"]')
            if computer is None:
                # 如果没有找到，尝试按位置查找
                computers = self.xml_root.findall('.//computer')
                if num-1 < len(computers):
                    computer = computers[num-1]
                else:
                    messagebox.showerror("错误", "无法找到对应的计算机节点")
                    logger("[修改数据]无法找到对应的计算机节点(几乎不可能出现这个问题)")
                    return
            
            # 更新计算机属性
            logger("[修改数据]将ip修改为"+new_values[0])
            computer.set('ip', new_values[0])
            logger("[修改数据]将节点名称修改为"+new_values[1])
            computer.set('name', new_values[1])
            
            # 更新防火墙信息
            firewall = computer.find('firewall')
            if firewall is not None:
                logger("[修改数据]将防火墙密码修改为"+new_values[0])
                firewall.set('solution', new_values[5])
            else:
                logger("[修改数据]创建防火墙数据并将防火墙密码修改为"+new_values[0])
                self.insert_firewall_after_links(computer, new_values[5])
            
            # 更新端口信息
            ports_open = computer.find('portsOpen')
            logger("[修改数据]将开放端口修改为"+new_values[6])
            if ports_open is not None:
                ports_open.text = new_values[6]
            else:
                logger("[修改数据]检测到坏档！问题：节点"+computer.get('name')+"的开放端口数据缺失！")
                return
                # ports_open = ET.SubElement(computer, 'portsOpen')
                # ports_open.text = new_values[6]

            # 更新解锁情况
            num = int(item[1:], 16)-1
            logger("[修改数据]程序进行到更新解锁情况")
            if new_values[2] == "是":
                logger("[修改数据]用户填写是")
                if num in self.computer_unlock_list:
                    pass
                else:
                    self.computer_unlock_list.append(num)          
            elif new_values[2] == "否":
                logger("[修改数据]用户填写否")
                if num in self.computer_unlock_list:
                    self.computer_unlock_list.remove(num)
                else:
                    pass
            else:
                logger("[修改数据]用户乱填解锁情况,此条目无效")
                pass
            logger("[修改数据]当前解锁状况数组："+str(self.computer_unlock_list))
            logger("[修改数据]程序进行到写入解锁情况")
            computer_unlock_list = ' '.join([str(i) for i in self.computer_unlock_list])
            logger("[修改数据]生成字符串，内容："+computer_unlock_list)
            self.xml_root.find('NetworkMap').find("visible").text = computer_unlock_list
            logger("[修改数据]解锁情况写入成功！")
            
            # 更新安全信息
            security = computer.find('security')
            if security is not None:
                logger("[修改数据]将追踪时间修改为"+new_values[7])
                security.set('traceTime', new_values[7])
                logger("[修改数据]将破解所需端口数修改为"+new_values[8])
                security.set('portsToCrack', new_values[8])
                if new_values[3] == "是":
                    logger("[修改数据]将是否为管理员修改为是")
                    security.set('adminIP', self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip'))
                elif new_values[3] == "否":
                    logger("[修改数据]将是否为管理员修改为否")
                    security.set('adminIP', "")
                else:
                    logger("[修改数据]用户乱填管理员，此条目无效")
                    pass
                
            else:
                logger("[修改数据]检测到坏档！问题：节点"+computer.get('name')+"的安全数据缺失！")
                # security = ET.SubElement(computer, 'security')
                # security.set('traceTime', new_values[7])
                # security.set('portsToCrack', new_values[8])
                # if new_values[3] == "是":
                #     security.set('adminIP', self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip'))
                # else:
                #     security.set('adminIP', "")
            
            window.destroy()
            self.showComputer()
            
        confirm_button = Button(window, text="确认", command=apply_edit)
        confirm_button.grid(row=len(tree["columns"]), column=0, columnspan=2)

if __name__ == "__main__":
    logger("[主程序]程序启动，当前版本为："+str(version)+"，debug模式开启")
    app = Win(Controller())
    logger("[主程序]控制器绑定成功，主程序开始")
    app.mainloop()
