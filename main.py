import random
import re
import struct
from tkinter import *
from tkinter import filedialog, messagebox
from tkinter.ttk import *
import xml.etree.ElementTree as ET
import string
import os


#--------------变量控制区-----------------
version = 1.03
debug = False
#-----------------------------------------


# ==================== DEC 解密核心 ====================
MULTIPLIER = 1822
OFFSET_BASE = 32767
EMPTY_PASSCODE = 5886
MEMORY_PASSCODE = 23248

def decrypt_num(num: int, passcode: int):
    off = OFFSET_BASE + passcode
    if (num - off) % MULTIPLIER != 0:
        return None
    ch = (num - off) // MULTIPLIER
    if 0 <= ch <= 0x10FFFF:
        return chr(ch)
    return None

def decrypt_block(encrypted: str, passcode: int):
    if not encrypted.strip():
        return ''
    res = []
    for part in encrypted.split():
        try:
            n = int(part)
        except:
            return None
        c = decrypt_num(n, passcode)
        if c is None:
            return None
        res.append(c)
    return ''.join(res)

def brute_force_passcode(encrypted_encoded: str, encrypted_content: str):
    if not encrypted_encoded.strip():
        return None
    nums_enc = [int(x) for x in encrypted_encoded.split()]
    n0_enc = nums_enc[0]
    for pc in range(0x10000):
        if (n0_enc - OFFSET_BASE - pc) % MULTIPLIER != 0:
            continue
        if (n0_enc - OFFSET_BASE - pc) // MULTIPLIER != ord('E'):
            continue
        dec_enc = []
        ok = True
        for n in nums_enc[1:]:
            off = OFFSET_BASE + pc
            if (n - off) % MULTIPLIER != 0:
                ok = False
                break
            ch = (n - off) // MULTIPLIER
            if ch < 0 or ch > 0x10FFFF:
                ok = False
                break
            dec_enc.append(ch)
        if not ok or len(dec_enc) != 6 or ''.join(chr(c) for c in dec_enc) != "NCODED":
            continue
        if encrypted_content.strip():
            nums_con = [int(x) for x in encrypted_content.split()]
            for n in nums_con:
                off = OFFSET_BASE + pc
                if (n - off) % MULTIPLIER != 0:
                    ok = False
                    break
            if not ok:
                continue
        return pc
    return None

def decrypt_layer(data: str, passcode: int):
    lines = [line for line in re.split(r'\r?\n', data) if line.strip() != '']
    if len(lines) < 2:
        raise ValueError("需要至少两行")
    head_line = lines[0]
    body_line = lines[1] if len(lines) > 1 else ''
    parts = head_line.split('::')
    if len(parts) < 4:
        raise ValueError("头部字段不足")
    header = decrypt_block(parts[1], EMPTY_PASSCODE)
    ip = decrypt_block(parts[2], EMPTY_PASSCODE)
    encoded = decrypt_block(parts[3], passcode)
    suffix = decrypt_block(parts[4], EMPTY_PASSCODE) if len(parts) > 4 else '.txt'
    if None in (header, ip, encoded, suffix):
        raise ValueError("头部解密失败")
    if encoded != "ENCODED":
        raise ValueError("密码错误")
    content = decrypt_block(body_line, passcode) if body_line else ''
    if content is None:
        raise ValueError("内容解密失败")
    return header, ip, suffix, content

def decrypt_all_layers(data: str):
    current_data = data
    first_header = first_ip = None
    final_suffix = '.txt'
    passcodes = []
    while True:
        lines = [line for line in re.split(r'\r?\n', current_data) if line.strip() != '']
        if len(lines) < 2:
            break
        head_line = lines[0]
        body_line = lines[1]
        parts = head_line.split('::')
        if len(parts) < 4:
            break
        encrypted_encoded = parts[3]
        pc = brute_force_passcode(encrypted_encoded, body_line)
        if pc is None:
            raise ValueError("无法爆破 passcode")
        passcodes.append(pc)
        header, ip, suffix, content = decrypt_layer(current_data, pc)
        if first_header is None:
            first_header = header
            first_ip = ip
        final_suffix = suffix
        if '#DEC_ENC' in content:
            current_data = content
        else:
            final_content = content
            break
    return first_header, first_ip, final_suffix, final_content, passcodes

def collect_dec_files_from_folder(folder_elem, current_path, ip, name, computer_elem, results):
    for child in folder_elem:
        if child.tag == 'folder':
            folder_name = child.get('name')
            if folder_name.lower() in ('log', 'sys'):
                continue
            if folder_name == '/':
                collect_dec_files_from_folder(child, current_path, ip, name, computer_elem, results)
            else:
                new_path = f"{current_path}/{folder_name}" if current_path else folder_name
                collect_dec_files_from_folder(child, new_path, ip, name, computer_elem, results)
        elif child.tag == 'file':
            file_name = child.get('name')
            if file_name.lower().endswith('.dec'):
                content = child.text.strip() if child.text else ''
                if not content.startswith('#DEC_ENC::'):
                    continue
                full_path = f"{current_path}/{file_name}" if current_path else file_name
                address = f"{ip}/{full_path}"
                results.append((file_name, name, address, content, ip, computer_elem))

# ==================== .NET Framework 4.0 哈希模拟 ====================
def dotnet_fx40_string_hash(s: str) -> int:
    encoded = s.encode('utf-16-le')
    length = len(s)
    ints = []
    for i in range(0, len(encoded), 4):
        chunk = encoded[i:i+4]
        if len(chunk) < 4:
            chunk = chunk + b'\x00' * (4 - len(chunk))
        ints.append(struct.unpack('<I', chunk)[0])
    def to_signed32(x):
        return x if x < 0x80000000 else x - 0x100000000
    num = 352654597
    num2 = num
    i = length
    idx = 0
    while i > 2:
        v1 = ints[idx]
        v2 = ints[idx + 1]
        num = to_signed32((((num << 5) + num + (num >> 27)) & 0xFFFFFFFF) ^ v1)
        num2 = to_signed32((((num2 << 5) + num2 + (num2 >> 27)) & 0xFFFFFFFF) ^ v2)
        idx += 2
        i -= 4
    if i > 0:
        v = ints[idx]
        num = to_signed32((((num << 5) + num + (num >> 27)) & 0xFFFFFFFF) ^ v)
    return to_signed32((num + num2 * 1566083941) & 0xFFFFFFFF)

def get_passcode(password: str) -> int:
    if password == "":
        return EMPTY_PASSCODE
    return dotnet_fx40_string_hash(password) & 0xFFFF

# ==================== 原工具代码 ====================
def logger(content):
    if debug:
        print(content)

def read_file(file):
    tree = ET.parse(file)
    root = tree.getroot()
    return root

def save_file(root, file):
    xml_str = ET.tostring(root, encoding='utf-8')
    with open(file, 'wb') as f:
        f.write('<?xml version ="1.0" encoding ="UTF-8" ?>\n'.encode() + xml_str)
    return 0

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
        menu.add_cascade(label="特殊", menu=self.menu_special(menu))  # 新特殊菜单
        return menu

    def __event_bind(self):
        self.protocol("WM_DELETE_WINDOW", self.ctl.quitApp)
        self.tk_table_m9v8rfji.bind('<Double-1>', self.ctl.open_file_browser)
        self.tk_table_m9v8rfji.bind('<Button-3>', self.ctl.show_context_menu)

    def menu_m9v8tcoh(self, parent):
        menu = Menu(parent, tearoff=False)
        menu.add_command(label="DEC文件查看器", command=self.ctl.showDECFiles)
        menu.add_command(label="内存转储查看器", command=self.ctl.showMemoryDumps)
        menu.add_command(label="DEC文件加解密器", command=self.ctl.showDECEncryptor)
        return menu

    def menu_special(self, parent):
        menu = Menu(parent, tearoff=False)
        menu.add_command(label="一键解锁全节点", command=self.ctl.unlockAllComputer)
        menu.add_command(label="一键获取全节点管理员权限", command=self.ctl.getAllComputerAdmin)
        menu.add_command(label="一键坚不可摧", command=self.ctl.makeMyComputerUnbreakable)
        menu.add_command(label="一键获得所有可执行文件", command=self.ctl.getAllExeFiles)
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

# ==================== 精确的随机数生成器 (MSRandom) ====================
class SubtractiveRNG:
    def __init__(self, seed):
        self._inext = 0
        self._inextp = 21
        self._seedArray = [0] * 56
        num2 = abs(seed) if seed != -2147483648 else 2147483647
        num3 = 161803398 - num2
        self._seedArray[55] = num3
        num4 = 1
        for i in range(1, 55):
            idx = (21 * i) % 55
            self._seedArray[idx] = num4
            num4 = num3 - num4
            if num4 < 0:
                num4 += 2147483647
            num3 = self._seedArray[idx]
        for _ in range(4):
            for k in range(1, 56):
                idx = k + 30
                if idx >= 55:
                    idx -= 55
                self._seedArray[k] -= self._seedArray[1 + idx]
                if self._seedArray[k] < 0:
                    self._seedArray[k] += 2147483647
        self._inext = 0
        self._inextp = 21

    def InternalSample(self):
        n1 = self._inext + 1
        if n1 >= 56:
            n1 = 1
        n2 = self._inextp + 1
        if n2 >= 56:
            n2 = 1
        val = self._seedArray[n1] - self._seedArray[n2]
        if val == 2147483647:
            val -= 1
        if val < 0:
            val += 2147483647
        self._seedArray[n1] = val
        self._inext = n1
        self._inextp = n2
        return val

    def NextBytes(self, buf):
        for i in range(len(buf)):
            buf[i] = self.InternalSample() & 0xFF

def gen_bin(rng, length=500):
    buf = [0] * (length // 8)
    rng.NextBytes(buf)
    return ''.join(bin(b)[2:] for b in buf)

def generate_all_exe_data():
    rng = SubtractiveRNG(17021990)
    exe_data = {}
    for port in [22, 21, 25, 80, 3724, 1433, 104, 3659]:
        exe_data[port] = gen_bin(rng)
    for port in [1, 4, 8, 9, 10, 11, 12]:
        exe_data[port] = gen_bin(rng)
    for port in [14, 15, 16, 17]:
        exe_data[port] = gen_bin(rng)
    exe_data[13] = gen_bin(rng)
    gen_bin(rng)
    gen_bin(rng)
    for port in [6881, 443, 31, 211, 32, 9418, 192, 33, 34, 35, 36, 37, 38, 39]:
        exe_data[port] = gen_bin(rng)
    gen_bin(rng)
    for port in [554, 40, 41]:
        exe_data[port] = gen_bin(rng)
    return exe_data

ALL_EXE_DATA = generate_all_exe_data()

EXE_NAMES = {
    22: "SSHcrack.exe", 21: "FTPBounce.exe", 25: "SMTPoverflow.exe",
    80: "WebServerWorm.exe", 3724: "WoWHack.exe", 1433: "SQL_MemCorrupt.exe",
    104: "KBT_PortTest.exe", 3659: "confloodEOS.exe",
    1: "Tutorial.exe", 4: "SecurityTracer.exe", 8: "Notes.exe",
    9: "Decypher.exe", 10: "DECHead.exe", 11: "Clock.exe",
    12: "TraceKill.exe", 13: "eosDeviceScan.exe", 14: "themechanger.exe",
    15: "hacknet.exe", 16: "HexClock.exe", 17: "Sequencer.exe",
    6881: "TorrentStreamInjector.exe", 443: "SSLTrojan.exe",
    31: "KaguyaTrial.exe", 211: "FTPSprint.exe", 32: "SignalScramble.exe",
    9418: "GitTunnel.exe", 192: "PacificPortcrusher.exe",
    33: "MemForensics.exe", 34: "MemDumpGenerator.exe",
    35: "NetmapOrganizer.exe", 36: "ComShell.exe", 37: "DNotes.exe",
    38: "ClockV2.exe", 39: "Tuneswap.exe", 554: "RTSPCrack.exe",
    40: "ESequencer.exe", 41: "OpShell.exe"
}

class Controller:
    ui = None
    xml_root = None
    computer_num = 0
    computer_unlock_list = None

    def __init__(self):
        pass

    def init(self, ui):
        self.ui = ui

    # ---------- 辅助方法 ----------
    def insert_firewall_after_links(self, parent_element, firewall_pass):
        children = list(parent_element)
        links_index = None
        for idx, child in enumerate(children):
            if child.tag == 'links':
                links_index = idx
                break
        if links_index is not None and links_index + 1 < len(children):
            next_sibling = children[links_index + 1]
            if next_sibling.tag == 'portsOpen':
                firewall = ET.SubElement(parent_element, 'firewall', {
                    'additionalDelay': '0', 'complexity': '0', 'solution': firewall_pass})
                parent_element.insert(links_index + 1, firewall)
        elif links_index is not None:
            firewall = ET.SubElement(parent_element, 'firewall', {
                'additionalDelay': '0', 'complexity': '0', 'solution': firewall_pass})
            parent_element.insert(links_index + 1, firewall)

    def get_computer_by_ip(self, ip):
        for comp in self.xml_root.findall('.//computer'):
            if comp.get('ip') == ip:
                return comp
        return None

    def get_player_computer(self):
        for comp in self.xml_root.findall('.//computer'):
            if comp.get('spec') == 'player':
                return comp
        return None

    def decode_hacknet_markers(self, text):
        if not text:
            return text
        replacements = {
            '|##LAB##|': '<',
            '|##RAB##|': '>',
            '|##QOT##|': '"',
            '|##SIQ##|': "'",
            '|##LSB##|': '[',
            '|##RSB##|': ']',
        }
        for marker, char in replacements.items():
            text = text.replace(marker, char)
        return text

    def get_memory_xml(self, computer):
        mem = computer.find('Memory')
        if mem is None:
            return ''
        return ET.tostring(mem, encoding='unicode').strip()

    def compact_memory_xml(self, raw_xml):
        compact = raw_xml
        compact = compact.replace("<Memory>", "<M>").replace("</Memory>", "</M>")
        compact = compact.replace("<Data>", "<D>").replace("</Data>", "</D>")
        compact = compact.replace("<Block>", "<b>").replace("</Block>", "</b>")
        compact = compact.replace("<Commands>", "<CM>").replace("</Commands>", "</CM>")
        compact = compact.replace("<Command>", "<c>").replace("</Command>", "</c>")
        compact = compact.replace("<FileFragments>", "<FF>").replace("</FileFragments>", "</FF>")
        compact = compact.replace("<File>", "<f>").replace("</File>", "</f>")
        compact = compact.replace("<Images>", "<Is>").replace("</Images>", "</Is>")
        compact = compact.replace("<Image>", "<i>").replace("</Image>", "</i>")
        compact = re.sub(r'>\s+<', '><', compact)
        return compact

    def encrypt_string(self, data: str, passcode: int) -> str:
        if not data:
            return ''
        parts = []
        for ch in data:
            num = ord(ch) * MULTIPLIER + OFFSET_BASE + passcode
            parts.append(str(num))
        return ' '.join(parts)

    def encrypt_dec_file(self, content: str, header: str, ip: str, password: str = "") -> str:
        pass_user = get_passcode(password) if password else EMPTY_PASSCODE
        enc_header = self.encrypt_string(header, EMPTY_PASSCODE)
        enc_ip = self.encrypt_string(ip, EMPTY_PASSCODE)
        enc_encoded = self.encrypt_string("ENCODED", pass_user)
        enc_suffix = self.encrypt_string(".txt", EMPTY_PASSCODE)
        enc_content = self.encrypt_string(content, pass_user)
        dec_line = f"#DEC_ENC::{enc_header}::{enc_ip}::{enc_encoded}::{enc_suffix}"
        return dec_line + "\r\n" + enc_content

    def encrypt_memory_dump(self, computer) -> str:
        raw_xml = self.get_memory_xml(computer)
        compact = self.compact_memory_xml(raw_xml)
        compact = re.sub(r'[\u4e00-\u9fff]', '?', compact)
        header_enc = self.encrypt_string("MEMORY DUMP", EMPTY_PASSCODE)
        ip_enc = self.encrypt_string("------", EMPTY_PASSCODE)
        encoded_enc = self.encrypt_string("ENCODED", MEMORY_PASSCODE)
        body_enc = self.encrypt_string(compact, MEMORY_PASSCODE)
        dec_line = f"#DEC_ENC::{header_enc}::{ip_enc}::{encoded_enc}"
        dec_content = dec_line + "\r\n" + body_enc
        header = "MEMORY_DUMP : FORMAT v1.22 ----------\n\n"
        bin_str = ''.join(random.choice('01') for _ in range(400))
        return header + bin_str + "\n\n" + dec_content

    def decrypt_memory_dump(self, data: str):
        header = "MEMORY_DUMP : FORMAT v1.22 ----------\n\n"
        if not data.startswith(header):
            return None
        bin_len = 400
        start_idx = len(header) + bin_len + 2
        if start_idx >= len(data):
            return None
        enc_part = data[start_idx:].strip()
        lines = [line for line in re.split(r'\r?\n', enc_part) if line.strip() != '']
        if len(lines) < 2:
            return None
        head_line = lines[0]
        body_line = lines[1] if len(lines) > 1 else ''
        parts = head_line.split('::')
        if len(parts) < 4:
            return None
        try:
            header_text = decrypt_block(parts[1], EMPTY_PASSCODE)
            ip_text = decrypt_block(parts[2], EMPTY_PASSCODE)
            encoded_text = decrypt_block(parts[3], MEMORY_PASSCODE)
            suffix = decrypt_block(parts[4], EMPTY_PASSCODE) if len(parts) > 4 else '.txt'
            if None in (header_text, ip_text, encoded_text, suffix):
                return None
            if encoded_text != "ENCODED":
                return None
            content = decrypt_block(body_line, MEMORY_PASSCODE)
            if content is None:
                return None
            return content
        except:
            return None

    def decrypt_all_layers_with_password(self, data: str, password: str):
        current_data = data
        first_header = first_ip = None
        final_suffix = '.txt'
        passcodes = []
        passcode = get_passcode(password) if password else EMPTY_PASSCODE
        while True:
            lines = [line for line in re.split(r'\r?\n', current_data) if line.strip() != '']
            if len(lines) < 2:
                break
            head_line = lines[0]
            body_line = lines[1]
            parts = head_line.split('::')
            if len(parts) < 4:
                break
            if decrypt_block(parts[3], passcode) != "ENCODED":
                raise ValueError("密码错误")
            header, ip, suffix, content = decrypt_layer(current_data, passcode)
            if first_header is None:
                first_header = header
                first_ip = ip
            final_suffix = suffix
            passcodes.append(passcode)
            if '#DEC_ENC' in content:
                current_data = content
            else:
                final_content = content
                break
        return first_header, first_ip, final_suffix, final_content, passcodes

    # ---------- 存档显示 ----------
    def showComputer(self):
        hacknet_save = self.xml_root
        if hacknet_save is None:
            messagebox.showerror("错误", "存档格式不正确")
            return
        game_user = hacknet_save.get('Username')
        if not game_user:
            game_user = "未知玩家"
        self.ui.title("Hacknet存档读取工具_v" + str(version) + " - 当前玩家：" + str(game_user))
        self.computer_unlock_list = list(map(int, self.xml_root.find('NetworkMap').find("visible").text.split()))
        for item in self.ui.tk_table_m9v8rfji.get_children():
            self.ui.tk_table_m9v8rfji.delete(item)
        self.computer_num = 0
        for computer in self.xml_root.findall('.//computer'):
            ip = computer.get('ip')
            name = computer.get('name')
            security = computer.find('security')
            trace_time = security.get('traceTime') if security is not None else ""
            ports_to_crack = security.get('portsToCrack') if security is not None else ""
            admin_ip = security.get('adminIP') if security is not None else ""
            ports = computer.find('portsOpen').text if computer.find('portsOpen') is not None else ""
            firewall = computer.find('firewall')
            firewall_solve = firewall.get('solution') if firewall is not None else ""
            admin_pass = ""
            users = computer.find('users')
            if users is not None:
                for user in users.findall('user'):
                    if user.get('name') == 'admin':
                        admin_pass = user.get('pass')
                        break
            player_ip = self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip')
            is_admin = "是" if admin_ip == player_ip else "否"
            is_unlocked = "是" if self.computer_num in self.computer_unlock_list else "否"
            data = [ip, name, is_unlocked, is_admin, admin_pass, firewall_solve, ports, trace_time, ports_to_crack]
            self.ui.tk_table_m9v8rfji.insert('', END, values=data)
            self.computer_num += 1

    # ---------- 文件操作 ----------
    def openFile(self):
        file_types = [('存档文件', '*.xml')]
        if os.name == 'nt':
            from win32com.shell import shellcon, shell
            default_path = shell.SHGetFolderPath(0, shellcon.CSIDL_PERSONAL, None, 0)+r"\My Games\Hacknet\Accounts"
        self.xml_file = filedialog.askopenfilename(title='打开存档',initialdir=default_path, filetypes=file_types)
        if not self.xml_file:
            return
        try:
            self.xml_root = read_file(self.xml_file)
        except Exception as e:
            messagebox.showinfo(message="存档不合法！请检查存档: " + str(e))
            return
        self.showComputer()

    def saveFile(self):
        if self.xml_root is None:
            messagebox.showinfo(message="请先打开一个存档！")
            return
        if messagebox.askyesno("确认", "你确定要覆盖保存存档吗？此行为不可逆"):
            save_file(self.xml_root, self.xml_file)
            messagebox.showinfo(message="存档保存成功！")

    def saveAnotherFile(self):
        if self.xml_root is None:
            messagebox.showinfo(message="请先打开一个存档！")
            return
        r = filedialog.asksaveasfilename(title='保存存档到', defaultextension=".xml", filetypes=[('存档文件', '*.xml')])
        if r:
            save_file(self.xml_root, r)
            messagebox.showinfo(message="存档保存成功！")

    def quitApp(self):
        if messagebox.askyesno("提示", "确定关闭软件？"):
            os._exit(0)

    # ---------- 特殊功能 ----------
    def unlockAllComputer(self):
        if self.xml_root is None: return messagebox.showinfo(message="请先打开一个存档！")
        self.xml_root.find('NetworkMap').find("visible").text = ' '.join(str(i) for i in range(self.computer_num))
        self.showComputer()
        messagebox.showinfo(message="全节点解锁获取完成！")

    def getAllComputerAdmin(self):
        if self.xml_root is None: return messagebox.showinfo(message="请先打开一个存档！")
        gamer_ip = self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip')
        for computer in self.xml_root.findall('.//computer'):
            sec = computer.find('security')
            if sec is not None: sec.set('adminIP', gamer_ip)
            users = computer.find('users')
            if users is not None:
                for u in users.findall('user'): u.set('known', 'True')
        self.showComputer()
        messagebox.showinfo(message="管理员权限获取完成！")

    def makeMyComputerUnbreakable(self):
        if self.xml_root is None: return messagebox.showinfo(message="请先打开一个存档！")
        player = self.get_player_computer()
        sec = player.find('security')
        if sec is None: sec = ET.SubElement(player, 'security')
        sec.set('portsToCrack', '9999998')
        sec.set('traceTime', '1')
        sec.set('proxyTime', '9999998')
        firewall = player.find('firewall')
        if firewall is None:
            self.insert_firewall_after_links(player, ''.join(random.choices(string.ascii_letters+string.digits, k=12)))
        else:
            firewall.set('solution', ''.join(random.choices(string.ascii_letters+string.digits, k=12)))
        ports = player.find('portsOpen')
        if ports is not None: ports.text = "80 25 21 22 1433 3659 104 443 192 6881 32 9418 3724 211 554"
        self.showComputer()
        messagebox.showinfo(message="你的电脑坚不可摧！[滑稽]")

    def getAllExeFiles(self):
        if self.xml_root is None:
            messagebox.showinfo(message="请先打开一个存档！")
            return
        player = self.get_player_computer()
        if player is None:
            messagebox.showerror("错误", "未找到玩家计算机")
            return
        filesystem = player.find('filesystem')
        if filesystem is None:
            messagebox.showerror("错误", "玩家计算机没有文件系统")
            return
        root = filesystem.find("folder[@name='/']")
        if root is None:
            messagebox.showerror("错误", "玩家计算机没有根文件夹")
            return
        bin_folder = root.find("folder[@name='bin']")
        if bin_folder is None:
            bin_folder = ET.SubElement(root, 'folder', {'name': 'bin'})
        added_count = 0
        skipped_count = 0
        for port, name in EXE_NAMES.items():
            existing = bin_folder.find(f"file[@name='{name}']")
            if existing is not None:
                skipped_count += 1
                continue
            data = ALL_EXE_DATA.get(port)
            if data is None:
                continue
            file_elem = ET.SubElement(bin_folder, 'file', {'name': name})
            file_elem.text = data
            file_elem.tail = '\n'
            added_count += 1
        messagebox.showinfo("完成", f"已添加 {added_count} 个文件，跳过已存在的 {skipped_count} 个。\n请手动保存存档以生效。")

    # ---------- 右键菜单与编辑 ----------
    def show_context_menu(self, event):
        item = self.ui.tk_table_m9v8rfji.identify_row(event.y)
        if item:
            self.ui.tk_table_m9v8rfji.selection_set(item)
            menu = Menu(self.ui, tearoff=False)
            menu.add_command(label="编辑", command=lambda: self.edit_row())
            menu.post(event.x_root, event.y_root)

    def edit_row(self):
        tree = self.ui.tk_table_m9v8rfji
        selection = tree.selection()
        if not selection: return
        item = selection[0]
        values = tree.item(item, 'values')
        window = Toplevel(self.ui)
        window.title("编辑行")
        entries = []
        for i, (col, val) in enumerate(zip(tree["columns"], values)):
            Label(window, text=col).grid(row=i, column=0, sticky="e")
            e = Entry(window); e.insert(0, val); e.grid(row=i, column=1, sticky="w")
            entries.append(e)

        def apply_edit():
            new_vals = [e.get() for e in entries]
            tree.item(item, values=new_vals)
            computer = self.xml_root.find(f'.//computer[@ip="{new_vals[0]}"]')
            if computer is None: computer = self.xml_root.findall('.//computer')[int(item[1:],16)-1]
            computer.set('ip', new_vals[0]); computer.set('name', new_vals[1])
            fw = computer.find('firewall')
            if fw is not None: fw.set('solution', new_vals[5])
            else: self.insert_firewall_after_links(computer, new_vals[5])
            ports = computer.find('portsOpen')
            if ports is not None: ports.text = new_vals[6]
            num = int(item[1:],16)-1
            if new_vals[2] == "是" and num not in self.computer_unlock_list:
                self.computer_unlock_list.append(num)
            elif new_vals[2] == "否" and num in self.computer_unlock_list:
                self.computer_unlock_list.remove(num)
            self.xml_root.find('NetworkMap').find("visible").text = ' '.join(map(str, self.computer_unlock_list))
            sec = computer.find('security')
            if sec is not None:
                sec.set('traceTime', new_vals[7]); sec.set('portsToCrack', new_vals[8])
                sec.set('adminIP', self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip') if new_vals[3]=="是" else "")
            window.destroy(); self.showComputer()

        Button(window, text="确认", command=apply_edit).grid(row=len(tree["columns"]), column=0, columnspan=2)

    # ==================== 文件浏览器 ====================
    def open_file_browser(self, event):
        tree = self.ui.tk_table_m9v8rfji
        item = tree.identify_row(event.y)
        if not item: return
        values = tree.item(item, 'values')
        if not values: return
        ip, name = values[0], values[1]
        computer = self.get_computer_by_ip(ip)
        if computer is None: return

        win = Toplevel(self.ui)
        win.title(f"文件浏览 - {name} ({ip})")
        win.geometry("900x600")

        paned = PanedWindow(win, orient=HORIZONTAL)
        paned.pack(fill=BOTH, expand=True)

        left = Frame(paned)
        paned.add(left)
        dir_tree = Treeview(left, show="tree")
        dir_tree.pack(side=LEFT, fill=BOTH, expand=True)
        sby = Scrollbar(left, command=dir_tree.yview)
        sby.pack(side=RIGHT, fill=Y)
        dir_tree.config(yscrollcommand=sby.set)

        right = Frame(paned)
        paned.add(right)
        text = Text(right, wrap=WORD, state=DISABLED)
        text.pack(side=LEFT, fill=BOTH, expand=True)
        sbr = Scrollbar(right, command=text.yview)
        sbr.pack(side=RIGHT, fill=Y)
        text.config(yscrollcommand=sbr.set)

        filesystem = computer.find('filesystem')
        if filesystem is not None:
            root_folder = filesystem.find("folder[@name='/']")
            if root_folder is not None:
                self._build_dir_tree(dir_tree, '', '/', root_folder)
                root_children = dir_tree.get_children('')
                if root_children:
                    dir_tree.item(root_children[0], open=True)

        mem_elem = computer.find('Memory')
        if mem_elem is not None:
            dir_tree.insert('', 'end', text='Memory', values=('__memory__',))

        def on_dir_select(event):
            sel = dir_tree.selection()
            if not sel: return
            item_data = dir_tree.item(sel[0])
            path = item_data['values'][0] if item_data['values'] else None
            if path is None:
                return
            if path == '__memory__':
                raw_xml = self.get_memory_xml(computer)
                compact = self.compact_memory_xml(raw_xml)
                content = self.decode_hacknet_markers(compact)
                text.config(state=NORMAL)
                text.delete(1.0, END)
                text.insert(1.0, content)
                text.config(state=DISABLED)
                return
            if path.endswith('/'):
                text.config(state=NORMAL)
                text.delete(1.0, END)
                text.config(state=DISABLED)
                return

            elem = self._find_fs_element(computer, path)
            if elem is None or elem.tag != 'file': return
            content = elem.text or ''
            fname = elem.get('name')

            if fname.lower().endswith('.dec') and content.startswith('#DEC_ENC::'):
                try:
                    _, _, _, final, _ = self.decrypt_all_layers_with_password(content, "")
                    final = self.decode_hacknet_markers(final)
                    text.config(state=NORMAL)
                    text.delete(1.0, END)
                    text.insert(1.0, final)
                    text.config(state=DISABLED)
                    return
                except:
                    pass
                # 弹窗
                def show_decrypted(result_text):
                    text.config(state=NORMAL)
                    text.delete(1.0, END)
                    text.insert(1.0, result_text)
                    text.config(state=DISABLED)

                dlg = Toplevel(win)
                dlg.title(f"解密 - {fname}")
                dlg.geometry("300x120")
                dlg.resizable(False, False)
                Label(dlg, text="输入密码（留空则使用默认空密码）：").pack(pady=5)
                pwd_entry = Entry(dlg, width=30)
                pwd_entry.pack(pady=5)
                pwd_entry.focus_set()

                def try_pwd():
                    password = pwd_entry.get()
                    dlg.destroy()
                    try:
                        _, _, _, final, _ = self.decrypt_all_layers_with_password(content, password)
                        final = self.decode_hacknet_markers(final)
                        show_decrypted(final)
                    except Exception as e:
                        messagebox.showerror("解密失败", str(e))

                def brute():
                    dlg.destroy()
                    try:
                        _, _, _, final, _ = decrypt_all_layers(content)
                        final = self.decode_hacknet_markers(final)
                        show_decrypted(final)
                    except Exception as e:
                        messagebox.showerror("解密失败", str(e))

                btn_frame = Frame(dlg)
                btn_frame.pack(pady=5)
                Button(btn_frame, text="确定", command=try_pwd, width=10).pack(side=LEFT, padx=5)
                Button(btn_frame, text="暴力破解", command=brute, width=10).pack(side=LEFT, padx=5)
                return

            if fname.lower().endswith('.mem'):
                if content.startswith('MEMORY_DUMP : FORMAT v1.22 ----------'):
                    mem_content = self.decrypt_memory_dump(content)
                    if mem_content is not None:
                        content = self.decode_hacknet_markers(mem_content)
                    else:
                        idx = content.find('#DEC_ENC::')
                        if idx != -1:
                            enc_part = content[idx:]
                            try:
                                _, _, _, final, _ = decrypt_all_layers(enc_part)
                                content = final
                            except:
                                pass
                else:
                    idx = content.find('#DEC_ENC::')
                    if idx != -1:
                        enc_part = content[idx:]
                        try:
                            _, _, _, final, _ = decrypt_all_layers(enc_part)
                            content = final
                        except:
                            pass

            content = self.decode_hacknet_markers(content)
            text.config(state=NORMAL)
            text.delete(1.0, END)
            text.insert(1.0, content)
            text.config(state=DISABLED)

        dir_tree.bind('<<TreeviewSelect>>', on_dir_select)

    def _build_dir_tree(self, tree, parent_node, parent_path, folder_elem):
        folder_name = folder_elem.get('name')
        if folder_name == '/':
            current_path = '/'
        else:
            current_path = (parent_path.rstrip('/') + '/' + folder_name) if parent_path != '/' else '/' + folder_name
        node = tree.insert(parent_node, 'end', text=folder_name, values=(current_path,))
        has_children = False
        for child in folder_elem:
            if child.tag == 'folder':
                self._build_dir_tree(tree, node, current_path, child)
                has_children = True
            elif child.tag == 'file':
                fname = child.get('name')
                fpath = current_path.rstrip('/') + '/' + fname
                tree.insert(node, 'end', text=fname, values=(fpath,))
                has_children = True
        if not has_children:
            tree.insert(node, 'end', text='-空白-', values=('',))

    def _find_fs_element(self, computer, path):
        fs = computer.find('filesystem')
        if fs is None: return None
        root = fs.find("folder[@name='/']")
        if path == '/' or path == '':
            return root
        parts = [p for p in path.strip('/').split('/') if p]
        cur = root
        for i, part in enumerate(parts):
            found = None
            for f in cur.findall('folder'):
                if f.get('name') == part:
                    found = f
                    break
            if found is not None:
                cur = found
                continue
            if i == len(parts) - 1:
                for f in cur.findall('file'):
                    if f.get('name') == part:
                        return f
            return None
        return cur

    # ==================== 内存转储查看器 ====================
    def showMemoryDumps(self):
        if self.xml_root is None:
            messagebox.showinfo(message="请先打开一个存档！")
            return
        dumps = []
        for computer in self.xml_root.findall('.//computer'):
            if computer.find('Memory') is not None:
                ip = computer.get('ip')
                name = computer.get('name')
                dumps.append((ip, name, computer))
        if not dumps:
            messagebox.showinfo(message="存档中没有包含内存转储的节点！")
            return
        window = Toplevel(self.ui)
        window.title("内存转储查看器")
        window.geometry("600x400")
        columns = ("IP", "节点名称")
        tree = Treeview(window, show="headings", columns=columns)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor='center', width=250)
        tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        for ip, name, _ in dumps:
            tree.insert('', END, values=(ip, name))

        def on_dbl_click(event):
            item = tree.selection()
            if not item: return
            vals = tree.item(item[0], 'values')
            ip, name = vals[0], vals[1]
            comp = next((c for c in dumps if c[0] == ip and c[1] == name), None)
            if comp is None: return
            computer = comp[2]
            raw_xml = self.get_memory_xml(computer)
            compact = self.compact_memory_xml(raw_xml)
            mem_content = self.decode_hacknet_markers(compact)
            result_win = Toplevel(self.ui)
            result_win.title(f"内存转储 - {name} ({ip})")
            result_win.geometry("800x600")
            menubar = Menu(result_win)
            file_menu = Menu(menubar, tearoff=False)
            file_menu.add_command(label="保存到玩家转储目录", command=lambda: self._save_to_memdump(computer, name))
            file_menu.add_command(label="保存到本地", command=lambda: self._save_memory_local(name, mem_content))
            menubar.add_cascade(label="文件", menu=file_menu)
            result_win.config(menu=menubar)
            text = Text(result_win, wrap=WORD)
            text.insert(1.0, mem_content)
            text.config(state=DISABLED)
            text.pack(fill=BOTH, expand=True, padx=10, pady=10)

        tree.bind('<Double-1>', on_dbl_click)

    def _save_to_memdump(self, computer, display_name):
        try:
            mem_content = self.encrypt_memory_dump(computer)
            self.save_memdump(computer, mem_content)
        except Exception as e:
            messagebox.showerror("错误", f"生成内存转储文件失败：{str(e)}")

    def save_memdump(self, computer, mem_content):
        player = self.get_player_computer()
        if player is None:
            messagebox.showerror("错误", "未找到玩家计算机")
            return
        fs = player.find('filesystem')
        if fs is None: return
        root = fs.find("folder[@name='/']")
        if root is None: return
        home = root.find("folder[@name='home']")
        if home is None:
            home = ET.SubElement(root, 'folder', {'name': 'home'})
        memdumps = home.find("folder[@name='MemDumps']")
        if memdumps is None:
            memdumps = ET.SubElement(home, 'folder', {'name': 'MemDumps'})
        filename = computer.get('name').replace(' ', '_').lower() + "_dump.mem"
        existing = memdumps.find(f"file[@name='{filename}']")
        if existing is not None:
            if not messagebox.askyesno("文件已存在", f"文件 {filename} 已存在于 /home/MemDumps，是否覆盖？"):
                return
            memdumps.remove(existing)
        file_elem = ET.SubElement(memdumps, 'file', {'name': filename})
        file_elem.text = mem_content
        file_elem.tail = '\n'
        messagebox.showinfo("成功", f"内存转储已保存到玩家 /home/MemDumps/{filename}。\n请手动“覆盖保存”以写入存档。")

    def _save_memory_local(self, name, content):
        path = filedialog.asksaveasfilename(title="保存内存转储", initialfile=f"{name}_memory.txt")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("成功", f"内存转储已保存到 {path}")

    # ==================== DEC 文件查看器 ====================
    def showDECFiles(self):
        if self.xml_root is None:
            messagebox.showinfo(message="请先打开一个存档！")
            return
        dec_files = []
        for computer in self.xml_root.findall('.//computer'):
            ip = computer.get('ip')
            name = computer.get('name')
            filesystem = computer.find('filesystem')
            if filesystem is not None:
                root_folder = filesystem.find("folder[@name='/']")
                if root_folder is not None:
                    collect_dec_files_from_folder(root_folder, "", ip, name, computer, dec_files)
        if not dec_files:
            messagebox.showinfo(message="存档中没有找到 .dec 文件！")
            return
        window = Toplevel(self.ui)
        window.title("DEC 文件查看器")
        window.geometry("900x500")
        columns = ("文件名", "来源主机名", "地址")
        tree = Treeview(window, show="headings", columns=columns)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor='center', width=200)
        tree.pack(fill=BOTH, expand=True, padx=10, pady=10)
        for fname, hostname, addr, _, _, _ in dec_files:
            tree.insert('', END, values=(fname, hostname, addr))

        def on_dbl_click(event):
            item = tree.selection()
            if not item: return
            vals = tree.item(item[0], 'values')
            fname, hostname, addr = vals[0], vals[1], vals[2]
            content = next((e[3] for e in dec_files if e[0]==fname and e[1]==hostname and e[2]==addr), None)
            if not content: return

            def show_result(hdr, ip, suffix, final, passcodes):
                base = os.path.splitext(fname)[0]
                final_name = base + suffix
                result_win = Toplevel(self.ui)
                result_win.title(f"解密结果 - {fname}")
                result_win.geometry("800x600")
                menubar = Menu(result_win)
                file_menu = Menu(menubar, tearoff=False)
                file_menu.add_command(label="保存到玩家/home目录", command=lambda: self.save_to_home(final_name, final))
                file_menu.add_command(label="保存到本地", command=lambda: self.save_to_local(final_name, final))
                menubar.add_cascade(label="文件", menu=file_menu)
                result_win.config(menu=menubar)
                final = self.decode_hacknet_markers(final)
                text = Text(result_win, wrap=WORD)
                text.insert(1.0, f"# 元数据（DECHead）_\nHeader: {hdr}\nIP: {ip}\nName: {final_name}\nPasscode: {passcodes[0]}\n# 元数据结束\n\n{final}")
                text.config(state=DISABLED)
                text.pack(fill=BOTH, expand=True, padx=10, pady=10)

            # 尝试空密码
            try:
                hdr, ip, suffix, final, passcodes = self.decrypt_all_layers_with_password(content, "")
                show_result(hdr, ip, suffix, final, passcodes)
                return
            except:
                pass

            dlg = Toplevel(self.ui)
            dlg.title(f"解密 - {fname}")
            dlg.geometry("300x120")
            dlg.resizable(False, False)
            Label(dlg, text="输入密码（留空则使用默认空密码）：").pack(pady=5)
            pwd_entry = Entry(dlg, width=30)
            pwd_entry.pack(pady=5)
            pwd_entry.focus_set()

            def try_pwd():
                password = pwd_entry.get()
                dlg.destroy()
                try:
                    hdr, ip, suffix, final, passcodes = self.decrypt_all_layers_with_password(content, password)
                    show_result(hdr, ip, suffix, final, passcodes)
                except Exception as e:
                    messagebox.showerror("解密失败", str(e))

            def brute():
                dlg.destroy()
                try:
                    hdr, ip, suffix, final, passcodes = decrypt_all_layers(content)
                    show_result(hdr, ip, suffix, final, passcodes)
                except Exception as e:
                    messagebox.showerror("解密失败", str(e))

            btn_frame = Frame(dlg)
            btn_frame.pack(pady=5)
            Button(btn_frame, text="确定", command=try_pwd, width=10).pack(side=LEFT, padx=5)
            Button(btn_frame, text="暴力破解", command=brute, width=10).pack(side=LEFT, padx=5)

        tree.bind('<Double-1>', on_dbl_click)

    # ==================== DEC 文件加解密器（修正底部标签） ====================
    def showDECEncryptor(self):
        win = Toplevel(self.ui)
        win.title("DEC 文件加解密器")
        win.geometry("850x650")
        win.resizable(True, True)

        # 菜单
        menubar = Menu(win)
        file_menu = Menu(menubar, tearoff=False)

        def open_plain_file():
            path = filedialog.askopenfilename(title="打开明文文件", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
            if not path:
                return
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                plain_text.delete("1.0", END)
                plain_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("打开失败", str(e))

        def open_cipher_file():
            path = filedialog.askopenfilename(title="打开密文文件", filetypes=[("DEC 文件", "*.dec"), ("所有文件", "*.*")])
            if not path:
                return
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                cipher_text.delete("1.0", END)
                cipher_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("打开失败", str(e))

        def save_plain_file():
            content = plain_text.get("1.0", END).strip()
            if not content:
                messagebox.showwarning("无内容", "明文文本框为空，无法保存。")
                return
            path = filedialog.asksaveasfilename(title="保存明文文件", defaultextension=".txt",
                                                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("保存成功", f"文件已保存到 {path}")
            except Exception as e:
                messagebox.showerror("保存失败", str(e))

        def save_cipher_file():
            content = cipher_text.get("1.0", END).strip()
            if not content:
                messagebox.showwarning("无内容", "密文文本框为空，无法保存。")
                return
            path = filedialog.asksaveasfilename(title="保存密文文件", defaultextension=".dec",
                                                filetypes=[("DEC 文件", "*.dec"), ("所有文件", "*.*")])
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("保存成功", f"文件已保存到 {path}")
            except Exception as e:
                messagebox.showerror("保存失败", str(e))

        file_menu.add_command(label="打开 txt 明文", command=open_plain_file)
        file_menu.add_command(label="打开 dec 密文", command=open_cipher_file)
        file_menu.add_separator()
        file_menu.add_command(label="保存明文 txt", command=save_plain_file)
        file_menu.add_command(label="保存密文 dec", command=save_cipher_file)
        menubar.add_cascade(label="文件", menu=file_menu)
        win.config(menu=menubar)

        # 整体布局：三列 + 底部一行
        win.grid_columnconfigure(0, weight=1, uniform="col")
        win.grid_columnconfigure(1, weight=0)
        win.grid_columnconfigure(2, weight=1, uniform="col")
        win.grid_rowconfigure(0, weight=1)  # 文本框行伸缩
        win.grid_rowconfigure(1, weight=0)  # 底部行固定高度

        # 左侧明文区
        left_frame = Frame(win)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)
        Label(left_frame, text="明文内容").grid(row=0, column=0, sticky="w")
        plain_text = Text(left_frame, wrap=WORD, width=40, height=20)
        plain_text.grid(row=1, column=0, sticky="nsew")

        # 中间按钮（垂直居中）
        mid_frame = Frame(win, width=80)
        mid_frame.grid(row=0, column=1, sticky="ns", padx=10, pady=5)
        mid_frame.grid_propagate(False)
        btn_container = Frame(mid_frame)
        btn_container.place(relx=0.5, rely=0.5, anchor="center")

        def do_encrypt():
            plain = plain_text.get("1.0", END).strip()
            header = title_var.get().strip() or "Title"
            ip = ip_var.get().strip() or "127.0.0.1"
            password = pwd_var.get()
            try:
                cipher = self.encrypt_dec_file(plain, header, ip, password)
                cipher_text.delete("1.0", END)
                cipher_text.insert("1.0", cipher)
            except Exception as e:
                messagebox.showerror("加密失败", str(e))

        def do_decrypt():
            cipher = cipher_text.get("1.0", END).strip()
            if not cipher.startswith("#DEC_ENC::"):
                messagebox.showerror("格式错误", "密文必须以 #DEC_ENC:: 开头")
                return
            lines = cipher.replace('\r\n', '\n').split('\n')
            non_empty = [l for l in lines if l.strip() != '']
            if len(non_empty) < 2:
                messagebox.showerror("格式错误", "密文必须至少包含头部和内容两行")
                return
            header_fields = non_empty[0].split("::")
            if len(header_fields) < 4:
                messagebox.showerror("格式错误", "密文头部字段不足")
                return

            password = pwd_var.get()
            passcode = get_passcode(password) if password else EMPTY_PASSCODE
            try:
                hdr, ip, suffix, content = decrypt_layer(cipher, passcode)
                # 回填标题和 IP
                title_var.set(hdr)
                ip_var.set(ip)
                plain_text.delete("1.0", END)
                plain_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("解密失败", str(e))

        Button(btn_container, text="加密 →", command=do_encrypt, width=10).pack(pady=3)
        Button(btn_container, text="← 解密", command=do_decrypt, width=10).pack(pady=3)

        # 右侧密文区
        right_frame = Frame(win)
        right_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)
        Label(right_frame, text="密文内容").grid(row=0, column=0, sticky="w")
        cipher_text = Text(right_frame, wrap=WORD, width=40, height=20)
        cipher_text.grid(row=1, column=0, sticky="nsew")

        # ---------- 底部一行：标题、IP、密码（三个独立子 Frame） ----------
        bottom_frame = Frame(win)
        bottom_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=5)
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=1)
        bottom_frame.grid_columnconfigure(2, weight=1)

        # 标题
        title_frame = Frame(bottom_frame)
        title_frame.grid(row=0, column=0, sticky="ew", padx=5)
        Label(title_frame, text="标题:").pack(side=LEFT)
        title_var = StringVar(value="Title")
        Entry(title_frame, textvariable=title_var).pack(side=LEFT, expand=True, fill=X)

        # IP
        ip_frame = Frame(bottom_frame)
        ip_frame.grid(row=0, column=1, sticky="ew", padx=5)
        Label(ip_frame, text="IP:").pack(side=LEFT)
        ip_var = StringVar(value="127.0.0.1")
        Entry(ip_frame, textvariable=ip_var).pack(side=LEFT, expand=True, fill=X)

        # 密码
        pwd_frame = Frame(bottom_frame)
        pwd_frame.grid(row=0, column=2, sticky="ew", padx=5)
        Label(pwd_frame, text="密码:").pack(side=LEFT)
        pwd_var = StringVar()
        Entry(pwd_frame, textvariable=pwd_var).pack(side=LEFT, expand=True, fill=X)

    def save_to_home(self, filename, content):
        player = self.get_player_computer()
        if player is None:
            messagebox.showerror("错误", "未找到玩家计算机")
            return
        fs = player.find('filesystem')
        if fs is None: return
        root = fs.find("folder[@name='/']")
        if root is None: return
        home = root.find("folder[@name='home']")
        if home is None:
            home = ET.SubElement(root, 'folder', {'name': 'home'})
        existing = home.find(f"file[@name='{filename}']")
        if existing is not None:
            if not messagebox.askyesno("文件已存在", "覆盖吗？"):
                return
            home.remove(existing)
        fe = ET.SubElement(home, 'file', {'name': filename})
        fe.text = content
        fe.tail = '\n'
        messagebox.showinfo("成功", "文件已保存到玩家 /home。\n请手动“覆盖保存”以写入存档。")

    def save_to_local(self, filename, content):
        path = filedialog.asksaveasfilename(title="保存到本地", initialfile=filename)
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("成功", f"文件已保存到 {path}")

if __name__ == "__main__":
    app = Win(Controller())
    app.mainloop()
