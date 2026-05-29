import random
import re
import struct
import tkinter as tk
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from tkinter.ttk import *
import xml.etree.ElementTree as ET
import string
import os


#--------------变量控制区-----------------
version = 1.05
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
    idx = 0
    i = length
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
        width = 900      # 加宽以容纳新列
        height = 450
        screenwidth = self.winfo_screenwidth()
        screenheight = self.winfo_screenheight()
        geometry = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.geometry(geometry)
        self.minsize(width=800, height=400)   # 允许用户缩小但不能太小

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
        columns = {
            "IP": 120, "节点名称": 130, "解锁状态": 60, "管理员": 60,
            "管理员密码": 100, "防火墙密码": 100, "开放端口": 100,
            "追踪时间": 70, "代理时间": 70, "破解端口数": 70        # 代理时间放在追踪时间后
        }
        # 容器 Frame，填满整个窗口
        table_frame = Frame(parent)
        table_frame.pack(fill=BOTH, expand=True)

        tk_table = Treeview(table_frame, show="headings", columns=list(columns))
        for text, width in columns.items():
            tk_table.heading(text, text=text, anchor='center')
            tk_table.column(text, anchor='center', width=width, minwidth=40, stretch=True)

        # 垂直滚动条
        vsb = Scrollbar(table_frame, orient="vertical", command=tk_table.yview)
        # 水平滚动条
        hsb = Scrollbar(table_frame, orient="horizontal", command=tk_table.xview)

        tk_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # 布局：表格占主要区域，滚动条在边缘
        tk_table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # 让表格所在的行和列可以拉伸
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # 绑定自动隐藏效果（已有方法）
        self.scrollbar_autohide(vsb, hsb, tk_table)

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
        menu.add_cascade(label="特殊", menu=self.menu_special(menu))
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

# ==================== 主题枚举 ====================
THEME_NAMES = {
    "HacknetBlue": "Hacknet Blue (默认蓝)",
    "HacknetTeal": "Hacknet Teal (青色)",
    "HacknetYellow": "Hacknet Yellow (黄色)",
    "HackerGreen": "Hacker Green (绿色)",
    "HacknetWhite": "Hacknet White (白色)",
    "HacknetPurple": "Hacknet Purple (紫色)",
    "HacknetMint": "Hacknet Mint (薄荷)",
    "TerminalOnlyBlack": "Terminal Only Black (纯黑终端)",
    "Colamaeleon": "Colamaeleon",
    "GreenCompact": "Green Compact",
    "Riptide": "Riptide",
    "Riptide2": "Riptide 2",
}
DEFAULT_THEME = "HacknetTeal"

# ==================== 守护进程定义 ====================
# 守护进程类型：(标签名, 属性列表)
DAEMON_DEFS = {
    "无": (None, []),
    "MailServer": ("MailServer", ["name", "color"]),
    "UploadServerDaemon": ("UploadServerDaemon", ["name", "foldername", "color", "needsAuth", "hasReturnViewButton"]),
    "WebServer": ("WebServer", ["name", "url"]),
    "DeathRowDatabase": ("DeathRowDatabase", []),
    "AcademicDatabse": ("AcademicDatabse", ["name"]),
    "ispSystem": ("ispSystem", []),
    "MessageBoard": ("MessageBoard", ["name", "boardName"]),
    "MedicalDatabase": ("MedicalDatabase", []),
    "HeartMonitor": ("HeartMonitor", ["patient"]),
    "PointClicker": ("PointClicker", []),
    "SongChangerDaemon": ("SongChangerDaemon", []),
    "MissionListingServer": ("MissionListingServer", ["name", "group", "public", "assign", "title", "icon", "color", "articles"]),
    "MissionHubServer": ("MissionHubServer", []),
    "DLCCredits": ("DLCCredits", ["Title", "Button", "Action"]),
    "LogoDaemon": ("LogoDaemon", ["LogoImagePath", "ShowsTitle", "TextColor", "Name"]),
    "LogoCustomConnectDisplayDaemon": ("LogoCustomConnectDisplayDaemon", ["logo", "title", "overdrawLogo", "buttonAlignment"]),
    "WhitelistAuthenticatorDaemon": ("WhitelistAuthenticatorDaemon", ["SelfAuthenticating"]),
    "MarkovTextDaemon": ("MarkovTextDaemon", ["Name", "SourceFilesContentFolder"]),
    "IRCDaemon": ("IRCDaemon", []),
}

ALL_PORTS = [80, 25, 21, 22, 1433, 3659, 104, 443, 192, 6881, 32, 9418, 3724, 211, 554]
PORT_NAMES = {
    80: "HTTP WebServer",
    25: "SMTP MailServer",
    21: "FTP Server",
    22: "SSH",
    1433: "SQL Server",
    3659: "eOS Connection Manager",
    104: "Medical Services",
    443: "HTTPS (SSL)",
    192: "Pacific Dedicated",
    6881: "BitTorrent",
    32: "SignalScramble",
    9418: "Version Control",
    3724: "Blizzard Updater",
    211: "Transfer",
    554: "RTSP",
}

# ==================== 游戏内置主题数据 ====================
THEME_DATA = {
    "HacknetBlue": "7297991071101011166610811710149",
    "HacknetTeal": "729799107110101116841019710850",
    "HackerGreen": "7297991071011147111410110111052",
    "HacknetWhite": "7297991071101011168710410511610153",
    "HacknetPurple": "7297991071101011168011711411210810154",
    "HacknetYellow": "7297991071101011168910110810811111951",
    "HacknetMint": "7297991071101011167710511011655",
    }
DEFAULT_THEME = "HacknetTeal"
    
class Controller:
    ui = None
    xml_root = None
    computer_num = 0
    computer_unlock_list = None
    clipboard = None

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

    def encode_hacknet_markers(self, text: str) -> str:
        """将普通字符转换为 Hacknet 存档标记"""
        if not text:
            return text
        replacements = {
            '<': '|##LAB##|',
            '>': '|##RAB##|',
            '"': '|##QOT##|',
            "'": '|##SIQ##|',
            '[': '|##LSB##|',
            ']': '|##RSB##|',
        }
        for char, marker in replacements.items():
            text = text.replace(char, marker)
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
            proxy_time = security.get('proxyTime') if security is not None else ""
            if proxy_time is None:
                proxy_time = ""
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
            data = [ip, name, is_unlocked, is_admin, admin_pass, firewall_solve, ports, trace_time, proxy_time, ports_to_crack]
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
            # 获取该行 IP
            values = self.ui.tk_table_m9v8rfji.item(item, 'values')
            if not values:
                return
            ip = values[0]

            # 查找对应的 computer 元素
            computer_elem = None
            for comp in self.xml_root.findall('.//computer'):
                if comp.get('ip') == ip:
                    computer_elem = comp
                    break

            # 根据 editor 属性判断是否可删除
            can_delete = (computer_elem is not None and computer_elem.get('editor') == 'true')

            menu = Menu(self.ui, tearoff=False)
            menu.add_command(label="编辑", command=lambda: self.edit_row())
            menu.add_command(label="新建节点", command=self.createNewComputer)
            menu.add_command(label="删除节点", command=lambda: self.deleteComputer(ip),
                             state="normal" if can_delete else "disabled")
            menu.post(event.x_root, event.y_root)

    def deleteComputer(self, ip):
        """删除指定 IP 的节点（仅限 editor="true" 的自定义节点）"""
        if self.xml_root is None:
            return

        computer_elem = None
        for comp in self.xml_root.findall('.//computer'):
            if comp.get('ip') == ip:
                computer_elem = comp
                break

        if computer_elem is None:
            messagebox.showerror("错误", "未找到该节点")
            return
        if computer_elem.get('editor') != 'true':
            messagebox.showwarning("提示", "该节点不是自定义节点，无法删除")
            return
        if computer_elem.get('spec') == 'player':
            messagebox.showwarning("提示", "不能删除玩家电脑")
            return

        if not messagebox.askyesno("确认删除", f"确定要删除节点 {computer_elem.get('name')} ({ip}) 吗？"):
            return

        # 获取被删除节点的原始索引（删除前的索引）
        all_comps = self.xml_root.findall('.//computer')
        old_index = list(all_comps).index(computer_elem)

        # 从 XML 中移除
        network = self.xml_root.find('.//network')
        if network is not None:
            network.remove(computer_elem)

        # 更新 visible 列表：移除被删除的索引，并将大于该索引的值减1
        visible_elem = self.xml_root.find('.//visible')
        if visible_elem is not None and visible_elem.text:
            visible_list = [int(x) for x in visible_elem.text.split()]
            new_visible = []
            for idx in visible_list:
                if idx == old_index:
                    continue       # 移除该索引
                elif idx > old_index:
                    new_visible.append(idx - 1)   # 后续索引前移
                else:
                    new_visible.append(idx)
            visible_elem.text = ' '.join(map(str, new_visible))

        # 更新计数
        self.computer_num = len(self.xml_root.findall('.//computer'))
        self.showComputer()
        messagebox.showinfo("成功", "节点已删除，请手动保存存档。")   

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
            if computer is None:
                computers = self.xml_root.findall('.//computer')
                num = int(item[1:], 16) - 1
                if num < len(computers):
                    computer = computers[num]
                else:
                    messagebox.showerror("错误", "无法找到对应的计算机节点")
                    return

            computer.set('ip', new_vals[0])
            computer.set('name', new_vals[1])

            fw = computer.find('firewall')
            if fw is not None:
                fw.set('solution', new_vals[5])
            else:
                self.insert_firewall_after_links(computer, new_vals[5])

            ports = computer.find('portsOpen')
            if ports is not None:
                ports.text = new_vals[6]

            num = int(item[1:], 16) - 1
            if new_vals[2] == "是" and num not in self.computer_unlock_list:
                self.computer_unlock_list.append(num)
            elif new_vals[2] == "否" and num in self.computer_unlock_list:
                self.computer_unlock_list.remove(num)
            self.xml_root.find('NetworkMap').find("visible").text = ' '.join(map(str, self.computer_unlock_list))

            sec = computer.find('security')
            if sec is not None:
                col_names = tree["columns"]
                # 定义需要动态处理的属性映射
                attr_map = {
                    "追踪时间": "traceTime",
                    "破解端口数": "portsToCrack",
                    "代理时间": "proxyTime",
                }
                for idx, col_name in enumerate(col_names):
                    if col_name in attr_map:
                        attr_name = attr_map[col_name]
                        new_val = new_vals[idx].strip()
                        if new_val == "":
                            # 如果原本有属性则删除
                            if sec.get(attr_name) is not None:
                                del sec.attrib[attr_name]
                        else:
                            sec.set(attr_name, new_val)
                    elif col_name == "管理员":
                        if new_vals[idx] == "是":
                            sec.set('adminIP', self.xml_root.find('.//NetworkMap/network/computer[1]').get('ip'))
                        else:
                            sec.set('adminIP', "")

            window.destroy()
            self.showComputer()

        Button(window, text="确认", command=apply_edit).grid(row=len(tree["columns"]), column=0, columnspan=2)
        
    # ==================== 文件浏览器（编辑版） ====================
    def open_file_browser(self, event):
        tree = self.ui.tk_table_m9v8rfji
        item = tree.identify_row(event.y)
        if not item: return
        values = tree.item(item, 'values')
        if not values: return
        ip, name = values[0], values[1]
        computer = self.get_computer_by_ip(ip)
        if computer is None: return

        original_computer_elem = self._deep_copy_element(computer)
        temp_computer_elem = self._deep_copy_element(computer)
        self.clipboard = None
        current_editing_path = None

        def check_modified():
            return ET.tostring(temp_computer_elem, encoding='unicode') != ET.tostring(original_computer_elem, encoding='unicode')

        def update_save_menu():
            if check_modified():
                file_menu.entryconfig("保存修改", state="normal")
            else:
                file_menu.entryconfig("保存修改", state="disabled")

        def save_modifications():
            nonlocal original_computer_elem, temp_computer_elem
            original_comp = self.get_computer_by_ip(ip)
            if original_comp is None: return
            temp_fs_root = temp_computer_elem.find('filesystem/folder[@name="/"]')
            if temp_fs_root is not None:
                self._sort_filesystem(temp_fs_root)
            orig_fs = original_comp.find('filesystem')
            temp_fs = temp_computer_elem.find('filesystem')
            if orig_fs is not None and temp_fs is not None:
                parent = original_comp
                idx = list(parent).index(orig_fs)
                parent.remove(orig_fs)
                parent.insert(idx, temp_fs)
            orig_mem = original_comp.find('Memory')
            temp_mem = temp_computer_elem.find('Memory')
            if temp_mem is not None:
                if orig_mem is not None:
                    parent = original_comp
                    idx = list(parent).index(orig_mem)
                    parent.remove(orig_mem)
                    parent.insert(idx, temp_mem)
                else:
                    original_comp.append(temp_mem)
            elif orig_mem is not None:
                original_comp.remove(orig_mem)
            original_computer_elem = self._deep_copy_element(original_comp)
            temp_computer_elem = self._deep_copy_element(original_comp)
            update_save_menu()
            self.showComputer()
            rebuild_tree()

        win = Toplevel(self.ui)
        win.title(f"文件浏览 - {name} ({ip})")
        win.geometry("900x600")

        menubar = Menu(win)
        file_menu = Menu(menubar, tearoff=False)
        file_menu.add_command(label="保存修改", command=save_modifications, state="disabled")
        file_menu.add_separator()
        file_menu.add_command(label="关闭窗口", command=win.destroy)
        menubar.add_cascade(label="文件", menu=file_menu)
        win.config(menu=menubar)

        address_frame = Frame(win)
        address_frame.pack(fill=X, padx=5, pady=2)
        Label(address_frame, text="路径:").pack(side=LEFT)
        address_var = StringVar()
        address_entry = Entry(address_frame, textvariable=address_var)
        address_entry.pack(side=LEFT, fill=X, expand=True)
        Button(address_frame, text="跳转", command=lambda: navigate(address_var.get())).pack(side=LEFT, padx=5)

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

        def on_edit(event):
            if current_editing_path is None:
                return
            elem = self._find_fs_element_by_path(temp_computer_elem, current_editing_path)
            if elem is not None and elem.tag == 'file':
                new_content = text.get("1.0", END).rstrip('\n')
                # 将编辑器中的正常字符转回 Hacknet 标记，以便正确保存到存档
                encoded_content = self.encode_hacknet_markers(new_content)
                elem.text = '\n' + encoded_content if encoded_content else None
                update_save_menu()
        text.bind("<KeyRelease>", on_edit)

        expanded_paths = set()
        def save_expanded():
            expanded_paths.clear()
            def collect_open(item):
                if dir_tree.item(item, 'open'):
                    expanded_paths.add(dir_tree.item(item, 'values')[0])
                for child in dir_tree.get_children(item):
                    collect_open(child)
            for root_child in dir_tree.get_children(''):
                collect_open(root_child)

        def restore_expanded():
            def expand_children(parent_item):
                for child in dir_tree.get_children(parent_item):
                    path = dir_tree.item(child, 'values')[0]
                    if path in expanded_paths:
                        dir_tree.item(child, open=True)
                    expand_children(child)
            for root_child in dir_tree.get_children(''):
                if dir_tree.item(root_child, 'values')[0] in expanded_paths:
                    dir_tree.item(root_child, open=True)
                expand_children(root_child)

        def rebuild_tree():
            save_expanded()
            for child in dir_tree.get_children():
                dir_tree.delete(child)
            filesystem = temp_computer_elem.find('filesystem')
            if filesystem is not None:
                root_folder = filesystem.find("folder[@name='/']")
                if root_folder is not None:
                    self._build_dir_tree_with_editing(dir_tree, '', '/', root_folder)
            mem_elem = temp_computer_elem.find('Memory')
            if mem_elem is not None:
                dir_tree.insert('', 'end', text='Memory', values=('__memory__',))
            restore_expanded()

        def get_current_dir():
            sel = dir_tree.selection()
            if sel:
                path = dir_tree.item(sel[0], 'values')[0]
                if path == '__memory__':
                    return '/'
                if path.endswith('/'):
                    return path
                return self._get_parent_path(path)
            return '/'

        def update_address():
            address_var.set(get_current_dir())

        def navigate(target):
            target = target.strip()
            if not target.endswith('/'):
                target += '/'
            folder = self._find_folder_by_path(temp_computer_elem, target)
            if folder is None:
                update_address()
                return
            found_item = None
            def select_item(parent, path_to_find):
                nonlocal found_item
                for child in dir_tree.get_children(parent):
                    if dir_tree.item(child, 'values')[0] == path_to_find:
                        found_item = child
                        dir_tree.selection_set(child)
                        dir_tree.see(child)
                        return True
                    if select_item(child, path_to_find):
                        return True
                return False
            if not select_item('', target):
                parts = target.strip('/').split('/')
                current_parent = ''
                for part in parts:
                    cur_path = '/' + '/'.join(parts[:parts.index(part)+1]) + '/'
                    for child in dir_tree.get_children(current_parent):
                        if dir_tree.item(child, 'values')[0] == cur_path:
                            dir_tree.item(child, open=True)
                            current_parent = child
                            break
                select_item('', target)
            if found_item:
                dir_tree.item(found_item, open=True)
            update_address()

        def on_dir_select(event):
            nonlocal current_editing_path
            sel = dir_tree.selection()
            if not sel: return
            item_data = dir_tree.item(sel[0])
            path = item_data['values'][0] if item_data['values'] else None
            if path is None: return
            update_address()
            if path == '__memory__':
                raw_xml = self.get_memory_xml(temp_computer_elem)
                compact = self.compact_memory_xml(raw_xml)
                content = self.decode_hacknet_markers(compact)
                text.config(state=NORMAL)
                text.delete(1.0, END)
                text.insert(1.0, content)
                text.config(state=DISABLED)
                current_editing_path = None
                return
            if path.endswith('/'):
                text.config(state=NORMAL)
                text.delete(1.0, END)
                text.config(state=DISABLED)
                current_editing_path = None
                return
            elem = self._find_fs_element_by_path(temp_computer_elem, path)
            if elem is None or elem.tag != 'file': return
            content = elem.text or ''
            fname = elem.get('name')
            if fname.lower().endswith('.dec') and content.startswith('#DEC_ENC::'):
                try:
                    _, _, _, final, _ = decrypt_all_layers(content)
                    content = final
                except: pass
            elif fname.lower().endswith('.mem'):
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
                        except: pass
            content = self.decode_hacknet_markers(content)
            text.config(state=NORMAL)
            text.delete(1.0, END)
            text.insert(1.0, content)
            current_editing_path = path

        dir_tree.bind('<<TreeviewSelect>>', on_dir_select)

        def on_right_click(event):
            item = dir_tree.identify_row(event.y)
            if item:
                dir_tree.selection_set(item)
                values = dir_tree.item(item, 'values')
                path = values[0] if values else None
                if path is None: return
                if path == '__memory__':
                    return
                is_folder = path.endswith('/')
                is_placeholder = path == ''
                if is_placeholder: return

                menu = Menu(win, tearoff=False)
                protected = is_folder and path in ['/', '/home/', '/log/', '/bin/', '/sys/']

                if is_folder:
                    menu.add_command(label="新建文件", command=lambda: create_new_file(path))
                    menu.add_command(label="新建文件夹", command=lambda: create_new_folder(path))
                    menu.add_separator()
                    menu.add_command(label="重命名", command=lambda: rename_item(path), state="disabled" if protected else "normal")
                    menu.add_command(label="复制", command=lambda: copy_item(path))
                    menu.add_separator()
                    menu.add_command(label="粘贴", command=lambda: paste_to_folder(path), state="normal" if self.clipboard else "disabled")
                    menu.add_separator()
                    menu.add_command(label="删除", command=lambda: delete_item(path), state="disabled" if protected else "normal")
                else:
                    menu.add_command(label="重命名", command=lambda: rename_item(path))
                    menu.add_separator()
                    menu.add_command(label="复制", command=lambda: copy_item(path))
                    menu.add_separator()
                    menu.add_command(label="粘贴", command=lambda: paste_to_file(path), state="normal" if self.clipboard else "disabled")
                    menu.add_separator()
                    menu.add_command(label="删除", command=lambda: delete_item(path))
                menu.post(event.x_root, event.y_root)

        def create_new_file(parent_path):
            name = simpledialog.askstring("新建文件", "输入文件名：", parent=win)
            if not name or name.strip() == '' or name == '-空白-':
                return
            folder_elem = self._find_folder_by_path(temp_computer_elem, parent_path)
            if folder_elem is None: return
            if folder_elem.find(f"file[@name='{name}']") is not None:
                messagebox.showwarning("错误", "文件已存在。")
                return
            file_elem = ET.SubElement(folder_elem, 'file', {'name': name})
            file_elem.tail = '\n'
            self._sort_folder_children(folder_elem)
            update_save_menu()
            rebuild_tree()

        def create_new_folder(parent_path):
            name = simpledialog.askstring("新建文件夹", "输入文件夹名：", parent=win)
            if not name or name.strip() == '' or name == '-空白-':
                return
            folder_elem = self._find_folder_by_path(temp_computer_elem, parent_path)
            if folder_elem is None: return
            if folder_elem.find(f"folder[@name='{name}']") is not None:
                messagebox.showwarning("错误", "文件夹已存在。")
                return
            new_folder = ET.SubElement(folder_elem, 'folder', {'name': name})
            new_folder.tail = '\n'
            self._sort_folder_children(folder_elem)
            update_save_menu()
            rebuild_tree()

        def rename_item(path):
            elem = self._find_fs_element_by_path(temp_computer_elem, path)
            if elem is None: return
            old_name = elem.get('name')
            new_name = simpledialog.askstring("重命名", f"输入新名称 (原: {old_name})：", initialvalue=old_name, parent=win)
            if not new_name or new_name.strip() == '' or new_name == '-空白-':
                return
            parent = self._find_parent_folder(temp_computer_elem, path)
            if parent is not None:
                tag = elem.tag
                if parent.find(f"{tag}[@name='{new_name}']") is not None:
                    messagebox.showwarning("错误", "名称已存在。")
                    return
            elem.set('name', new_name)
            update_save_menu()
            rebuild_tree()

        def copy_item(path):
            elem = self._find_fs_element_by_path(temp_computer_elem, path)
            if elem is None: return
            copied = self._deep_copy_element(elem)
            self.clipboard = (elem.tag, copied)

        def paste_to_folder(target_folder_path):
            folder_elem = self._find_folder_by_path(temp_computer_elem, target_folder_path)
            if folder_elem is None: return
            _do_paste(folder_elem)
            self._sort_folder_children(folder_elem)
            update_save_menu()
            rebuild_tree()

        def paste_to_file(file_path):
            parent_folder = self._find_parent_folder(temp_computer_elem, file_path)
            if parent_folder is None: return
            _do_paste(parent_folder)
            if parent_folder is not None:
                self._sort_folder_children(parent_folder)
            update_save_menu()
            rebuild_tree()

        def _do_paste(target_folder_elem):
            tag, copied_elem = self.clipboard
            if tag == 'file':
                file_name = copied_elem.get('name')
                existing = target_folder_elem.find(f"file[@name='{file_name}']")
                if existing is not None:
                    resolve = self._show_file_conflict(win, copied_elem.text or '', existing.text or '', file_name)
                    if resolve == 'overwrite':
                        target_folder_elem.remove(existing)
                    elif resolve == 'skip':
                        return
                target_folder_elem.append(self._deep_copy_element(copied_elem))
            elif tag == 'folder':
                folder_name = copied_elem.get('name')
                existing_folder = target_folder_elem.find(f"folder[@name='{folder_name}']")
                if existing_folder is not None:
                    self._merge_folders(existing_folder, copied_elem, win)
                else:
                    target_folder_elem.append(self._deep_copy_element(copied_elem))

        def delete_item(path):
            elem = self._find_fs_element_by_path(temp_computer_elem, path)
            if elem is None: return
            parent = self._find_parent_folder(temp_computer_elem, path)
            if parent is not None:
                parent.remove(elem)
            update_save_menu()
            rebuild_tree()

        dir_tree.bind('<Button-3>', on_right_click)

        def ctrl_s(event):
            if check_modified():
                save_modifications()
        win.bind('<Control-s>', ctrl_s)

        def on_close():
            if check_modified():
                answer = messagebox.askyesnocancel("未保存修改", "有未保存的修改，是否保存？")
                if answer is None:
                    return
                elif answer:
                    save_modifications()
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", on_close)

        rebuild_tree()
        root_children = dir_tree.get_children('')
        if root_children:
            dir_tree.item(root_children[0], open=True)
        update_address()

    def _sort_folder_children(self, folder_elem):
        children = list(folder_elem)
        folders = [c for c in children if c.tag == 'folder']
        files = [c for c in children if c.tag == 'file']
        for c in children:
            folder_elem.remove(c)
        for f in folders:
            folder_elem.append(f)
            f.tail = '\n'
        for f in files:
            folder_elem.append(f)
            f.tail = '\n'

    def _sort_filesystem(self, fs_root):
        self._sort_folder_children(fs_root)
        for child in fs_root:
            if child.tag == 'folder':
                self._sort_filesystem(child)

    def _get_parent_path(self, path):
        clean = path.rstrip('/')
        parent = '/'.join(clean.split('/')[:-1]) or '/'
        return parent if parent == '/' else parent + '/'

    def _build_dir_tree_with_editing(self, tree, parent_node, parent_path, folder_elem):
        folder_name = folder_elem.get('name')
        if folder_name == '/':
            current_path = '/'
        else:
            current_path = (parent_path.rstrip('/') + '/' + folder_name) if parent_path != '/' else '/' + folder_name
        if not current_path.endswith('/'):
            current_path += '/'
        node = tree.insert(parent_node, 'end', text=folder_name, values=(current_path,))
        has_children = False
        for child in folder_elem:
            if child.tag == 'folder':
                self._build_dir_tree_with_editing(tree, node, current_path, child)
                has_children = True
            elif child.tag == 'file':
                fname = child.get('name')
                fpath = current_path + fname
                tree.insert(node, 'end', text=fname, values=(fpath,))
                has_children = True
        if not has_children:
            tree.insert(node, 'end', text='-空白-', values=('',))

    def _find_fs_element_by_path(self, computer_elem, path):
        if path == '/' or path == '':
            return computer_elem.find('filesystem/folder[@name="/"]')
        clean_path = path.rstrip('/')
        parts = [p for p in clean_path.strip('/').split('/') if p]
        root = computer_elem.find('filesystem/folder[@name="/"]')
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
            for f in cur.findall('file'):
                if f.get('name') == part:
                    return f
            return None
        return cur

    def _find_folder_by_path(self, computer_elem, path):
        elem = self._find_fs_element_by_path(computer_elem, path)
        if elem is not None and elem.tag == 'folder':
            return elem
        return None

    def _find_parent_folder(self, computer_elem, path):
        if path == '/' or path == '':
            return None
        clean = path.rstrip('/')
        parent_clean = '/'.join(clean.split('/')[:-1]) or '/'
        parent_path = parent_clean if parent_clean == '/' else parent_clean + '/'
        return self._find_folder_by_path(computer_elem, parent_path)

    def _show_file_conflict(self, parent_win, clipboard_content, original_content, filename):
        win = Toplevel(parent_win)
        win.title("文件冲突")
        win.geometry("600x400")
        Label(win, text=f"文件 '{filename}' 已存在，如何处理？").pack(pady=5)
        paned = PanedWindow(win, orient=HORIZONTAL)
        paned.pack(fill=BOTH, expand=True, padx=5, pady=5)
        left_frame = Frame(paned)
        paned.add(left_frame)
        Label(left_frame, text="剪切板内容").pack()
        text1 = Text(left_frame, wrap=WORD)
        text1.insert(1.0, clipboard_content)
        text1.config(state=DISABLED)
        text1.pack(fill=BOTH, expand=True)
        right_frame = Frame(paned)
        paned.add(right_frame)
        Label(right_frame, text="原内容").pack()
        text2 = Text(right_frame, wrap=WORD)
        text2.insert(1.0, original_content)
        text2.config(state=DISABLED)
        text2.pack(fill=BOTH, expand=True)
        result = {'action': None}
        def set_action(act):
            result['action'] = act
            win.destroy()
        btn_frame = Frame(win)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="覆盖", command=lambda: set_action('overwrite')).pack(side=LEFT, padx=5)
        tk.Button(btn_frame, text="跳过", command=lambda: set_action('skip')).pack(side=LEFT, padx=5)
        win.wait_window()
        return result['action']

    def _merge_folders(self, target_folder, source_folder, win):
        for child in source_folder:
            tag = child.tag
            name = child.get('name')
            if tag == 'file':
                existing = target_folder.find(f"file[@name='{name}']")
                if existing is not None:
                    resolve = self._show_file_conflict(win, child.text or '', existing.text or '', name)
                    if resolve == 'overwrite':
                        target_folder.remove(existing)
                        target_folder.append(self._deep_copy_element(child))
                    elif resolve == 'skip':
                        continue
                else:
                    target_folder.append(self._deep_copy_element(child))
            elif tag == 'folder':
                existing_folder = target_folder.find(f"folder[@name='{name}']")
                if existing_folder is not None:
                    self._merge_folders(existing_folder, child, win)
                else:
                    target_folder.append(self._deep_copy_element(child))

    def _deep_copy_element(self, elem):
        return ET.fromstring(ET.tostring(elem, encoding='unicode'))

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
            memdumps.tail = '\n'
            self._sort_folder_children(home)
        raw_name = computer.get('name')
        safe_name = re.sub(r'[\u4e00-\u9fff]', '?', raw_name)
        filename = safe_name.replace(' ', '_').lower() + "_dump.mem"
        existing = memdumps.find(f"file[@name='{filename}']")
        if existing is not None:
            if not messagebox.askyesno("文件已存在", f"文件 {filename} 已存在于 /home/MemDumps，是否覆盖？"):
                return
            memdumps.remove(existing)
        file_elem = ET.SubElement(memdumps, 'file', {'name': filename})
        file_elem.text = mem_content
        file_elem.tail = '\n'
        self._sort_folder_children(memdumps)
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
            tk.Button(btn_frame, text="确定", command=try_pwd, width=10).pack(side=LEFT, padx=5)
            tk.Button(btn_frame, text="暴力破解", command=brute, width=10).pack(side=LEFT, padx=5)

        tree.bind('<Double-1>', on_dbl_click)

    # ==================== DEC 加解密器 ====================
    def showDECEncryptor(self):
        win = Toplevel(self.ui)
        win.title("DEC 文件加解密器")
        win.geometry("850x650")
        win.resizable(True, True)

        menubar = Menu(win)
        file_menu = Menu(menubar, tearoff=False)

        def open_plain_file():
            path = filedialog.askopenfilename(title="打开明文文件", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
            if not path: return
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                plain_text.delete("1.0", END)
                plain_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("打开失败", str(e))

        def open_cipher_file():
            path = filedialog.askopenfilename(title="打开密文文件", filetypes=[("DEC 文件", "*.dec"), ("所有文件", "*.*")])
            if not path: return
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                cipher_text.delete("1.0", END)
                cipher_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("打开失败", str(e))

        def save_plain_file():
            content = plain_text.get("1.0", END).strip()
            if not content: return
            path = filedialog.asksaveasfilename(title="保存明文文件", defaultextension=".txt",
                                                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
            if not path: return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
            except Exception as e:
                messagebox.showerror("保存失败", str(e))

        def save_cipher_file():
            content = cipher_text.get("1.0", END).strip()
            if not content: return
            path = filedialog.asksaveasfilename(title="保存密文文件", defaultextension=".dec",
                                                filetypes=[("DEC 文件", "*.dec"), ("所有文件", "*.*")])
            if not path: return
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
            except Exception as e:
                messagebox.showerror("保存失败", str(e))

        file_menu.add_command(label="打开 txt 明文", command=open_plain_file)
        file_menu.add_command(label="打开 dec 密文", command=open_cipher_file)
        file_menu.add_separator()
        file_menu.add_command(label="保存明文 txt", command=save_plain_file, state="disabled")
        file_menu.add_command(label="保存密文 dec", command=save_cipher_file, state="disabled")
        menubar.add_cascade(label="文件", menu=file_menu)
        win.config(menu=menubar)

        def update_plain_save_state():
            if plain_text.get("1.0", END).strip():
                file_menu.entryconfig("保存明文 txt", state="normal")
            else:
                file_menu.entryconfig("保存明文 txt", state="disabled")

        def update_cipher_save_state():
            if cipher_text.get("1.0", END).strip():
                file_menu.entryconfig("保存密文 dec", state="normal")
            else:
                file_menu.entryconfig("保存密文 dec", state="disabled")

        win.grid_columnconfigure(0, weight=1, uniform="col")
        win.grid_columnconfigure(1, weight=0)
        win.grid_columnconfigure(2, weight=1, uniform="col")
        win.grid_rowconfigure(0, weight=1)

        left_frame = Frame(win)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)
        Label(left_frame, text="明文内容").grid(row=0, column=0, sticky="w")
        plain_text = Text(left_frame, wrap=WORD, width=40, height=20)
        plain_text.grid(row=1, column=0, sticky="nsew")
        plain_text.bind("<KeyRelease>", lambda e: update_plain_save_state())

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
                title_var.set(hdr)
                ip_var.set(ip)
                plain_text.delete("1.0", END)
                plain_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("解密失败", str(e))

        tk.Button(btn_container, text="加密 →", command=do_encrypt, width=10).pack(pady=3)
        tk.Button(btn_container, text="← 解密", command=do_decrypt, width=10).pack(pady=3)

        right_frame = Frame(win)
        right_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)
        Label(right_frame, text="密文内容").grid(row=0, column=0, sticky="w")
        cipher_text = Text(right_frame, wrap=WORD, width=40, height=20)
        cipher_text.grid(row=1, column=0, sticky="nsew")
        cipher_text.bind("<KeyRelease>", lambda e: update_cipher_save_state())

        bottom_frame = Frame(win)
        bottom_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=5)
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=1)
        bottom_frame.grid_columnconfigure(2, weight=1)

        title_frame = Frame(bottom_frame)
        title_frame.grid(row=0, column=0, sticky="ew", padx=5)
        Label(title_frame, text="标题:").pack(side=LEFT)
        title_var = StringVar(value="Title")
        Entry(title_frame, textvariable=title_var).pack(side=LEFT, expand=True, fill=X)

        ip_frame = Frame(bottom_frame)
        ip_frame.grid(row=0, column=1, sticky="ew", padx=5)
        Label(ip_frame, text="IP:").pack(side=LEFT)
        ip_var = StringVar(value="127.0.0.1")
        Entry(ip_frame, textvariable=ip_var).pack(side=LEFT, expand=True, fill=X)

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


    # ==================== 节点创建 ====================
    def _generate_random_ip(self):
        return f"{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(0,254)}"

    def _get_unused_ip(self):
        existing_ips = {comp.get('ip') for comp in self.xml_root.findall('.//computer')}
        for _ in range(1000):
            ip = self._generate_random_ip()
            if ip not in existing_ips:
                return ip
        return self._generate_random_ip()

    def _generate_binary_string(self, length=500):
        byte_count = length // 8
        random_bytes = [random.randint(0, 255) for _ in range(byte_count)]
        return ''.join(bin(b)[2:] for b in random_bytes)

    def _get_daemon_resource(self, filename):
        """读取 DaemonResources 目录下的资源文件，若不存在则返回降级文本"""
        res_path = os.path.join(os.path.dirname(__file__), "DaemonResources", filename)
        if os.path.exists(res_path):
            with open(res_path, 'r', encoding='utf-8') as f:
                return f.read()
        return f"[Missing resource: {filename}]"

    def _load_people_from_xml(self):
        """解析 DaemonResources/People/ 下的所有人物 XML，返回 dict {id: data}"""
        people_dir = os.path.join(os.path.dirname(__file__), "DaemonResources", "People")
        if not os.path.isdir(people_dir):
            return {}

        people = {}
        for filename in os.listdir(people_dir):
            if not filename.endswith('.xml'):
                continue
            path = os.path.join(people_dir, filename)
            try:
                tree = ET.parse(path)
                root = tree.getroot()
            except:
                continue

            person = {
                'id': root.get('id', ''),
                'handle': root.get('handle', ''),
                'firstName': root.get('firstName', ''),
                'lastName': root.get('lastName', ''),
                'isMale': root.get('isMale', 'true').lower() == 'true',
                'degrees': [],
                'dob': '',
                'medical': {},
                'notes': ''
            }
            dob = root.find('DOB')
            if dob is not None and dob.text:
                person['dob'] = dob.text.strip()

            degrees = root.find('Degrees')
            if degrees is not None:
                for d in degrees.findall('Degree'):
                    person['degrees'].append({
                        'name': d.text or '',
                        'uni': d.get('uni', ''),
                        'gpa': d.get('gpa', '')
                    })

            med = root.find('Medical')
            if med is not None:
                blood = med.find('Blood')
                height = med.find('Height')
                allergies = med.find('Allergies')
                notes = med.find('Notes')
                prescriptions = med.findall('Perscription')
                person['medical'] = {
                    'blood': blood.text if blood is not None else '',
                    'height': height.text if height is not None else '',
                    'allergies': allergies.text if allergies is not None else '',
                    'prescriptions': [p.text or '' for p in prescriptions],
                    'notes': notes.text.strip() if notes is not None and notes.text else ''
                }

            notes_el = root.find('Notes')
            if notes_el is not None and notes_el.text:
                person['notes'] = notes_el.text.strip()

            people[person['id']] = person
        return people

    def _format_medical_record(self, person):
        """将人物数据格式化为 MedicalDatabase 的 .rec 文件内容"""
        first = person['firstName']
        last = person['lastName']
        gender = 'male' if person['isMale'] else 'female'
        dob = person['dob']
        med = person['medical']
        lines = []
        if med.get('blood'):
            lines.append(f"Blood Type: {med['blood']}")
        if med.get('height'):
            lines.append(f"Height: {med['height']}cm")
        if med.get('allergies'):
            lines.append(f"Allergies: {med['allergies']}")
        for p in med.get('prescriptions', []):
            lines.append(f"Prescription: {p}")
        if med.get('notes'):
            lines.append(f"Notes: {med['notes']}")
        record = '\n'.join(lines) if lines else "No medical data"
        return f"{first}\n-----------------\n{last}\n-----------------\n{gender}\n-----------------\n{dob}\n-----------------\n{record}"

    def _format_academic_record(self, person):
        """将人物数据格式化为 AcademicDatabase 的条目文本"""
        lines = [f"Name: {person['firstName']} {person['lastName']}"]
        for deg in person['degrees']:
            lines.append(f"{deg['name']} | {deg['uni']} | GPA: {deg['gpa']}")
        return '\n'.join(lines)

    def _parse_deathrow_records(self):
        """解析 DeathRow.txt + DeathRowSpecials.txt，返回囚犯记录列表"""
        res_dir = os.path.join(os.path.dirname(__file__), "DaemonResources")
        text = ""
        for fname in ["DeathRow.txt", "DeathRowSpecials.txt"]:
            path = os.path.join(res_dir, fname)
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    text += f.read()
        if not text:
            return []
        entries = text.split("\r\n###%%##%%##%%##\r\n")
        records = []
        for entry in entries:
            if not entry.strip():
                continue
            parts = entry.split('#')
            if len(parts) >= 2:
                records.append({
                    'fname': parts[0].strip(),
                    'lname': parts[1].strip(),
                    'data': entry
                })
        return records

    def _add_daemon_filesystems(self, comp, daemon_key, daemon_attrs, admin_pass):
        """根据守护进程类型，向文件系统中添加所需的文件夹和初始文件"""
        root = comp.find('filesystem/folder[@name="/"]')
        if root is None:
            return

        def ensure_folder(name, parent=None):
            if parent is None:
                parent = root
            folder = parent.find(f"folder[@name='{name}']")
            if folder is None:
                folder = ET.SubElement(parent, 'folder', {'name': name})
                folder.text = '\n'
                folder.tail = '\n'
            return folder

        def add_file(folder, filename, content):
            f = ET.SubElement(folder, 'file', {'name': filename})
            f.text = content
            f.tail = '\n'

        tag = DAEMON_DEFS[daemon_key][0]

        # ---------- AcademicDatabse ----------
        if tag == "AcademicDatabse":
            ad = ensure_folder("academic_data")
            ec = ensure_folder("entry_cache", parent=ad)
            add_file(ad, "info.txt", self._get_daemon_resource("AcademicDatabaseInfo.txt"))
            people = self._load_people_from_xml()
            if people:
                for pid, person in people.items():
                    if person['degrees']:
                        fname = f"{person['lastName'].lower()}_{person['firstName'].lower()}.txt"
                        if ec.find(f"file[@name='{fname}']") is None:
                            add_file(ec, fname, self._format_academic_record(person))

        # ---------- AircraftDaemon ----------
        elif tag == "AircraftDaemon":
            fs = ensure_folder("FlightSystems")
            dll_data = self._generate_binary_string(500)
            add_file(fs, "747FlightOps.dll", dll_data)
            for name in ["InFlightWifiRouter.dll", "Scheduler.dll", "EntertainmentServices.dll", "AnnouncementsSys.dll"]:
                add_file(fs, name, self._generate_binary_string(200))

        # ---------- DatabaseDaemon (跳过 VehicleInfo 和 NeopalsAccount) ----------
        elif tag == "DatabaseDaemon":
            dtype = (daemon_attrs or {}).get('DataType', '')
            if dtype.endswith("VehicleInfo") or dtype.endswith("NeopalsAccount"):
                # 无法还原，仅创建空文件夹
                folder_name = daemon_attrs.get('Foldername', 'Database')
                ensure_folder(folder_name)
            else:
                # 默认行为：创建文件夹并生成几个示例记录
                folder_name = daemon_attrs.get('Foldername', 'Database')
                db = ensure_folder(folder_name)
                for i in range(3):
                    add_file(db, f"record_{i}.rec", f"Sample record {i}")

        # ---------- DeathRowDatabase ----------
        elif tag == "DeathRowDatabase":
            dr = ensure_folder("dr_database")
            rec = ensure_folder("records", parent=dr)
            add_file(dr, "ServerDetails.txt", self._get_daemon_resource("DeathRowServerInfo.txt"))
            deathrows = self._parse_deathrow_records()
            if deathrows:
                for entry in deathrows:
                    fname = f"{entry['lname']}_{entry['fname']}[1]"
                    if rec.find(f"file[@name='{fname}']") is None:
                        data = entry['data'].replace('#', '#\n')
                        add_file(rec, fname, data)

        # ---------- HeartMonitor ----------
        elif tag == "HeartMonitor":
            kbt = ensure_folder("KBT_Pacemaker")
            active = ensure_folder("Active", parent=kbt)
            fw = self._generate_binary_string(500)
            add_file(kbt, "KBT_Firmware_v1.2.dll", fw)
            add_file(active, "LiveFirmware.dll", fw)

        # ---------- IRCDaemon ----------
        elif tag == "IRCDaemon":
            irc = ensure_folder("IRC")
            runtime = ensure_folder("runtime", parent=irc)
            cfg = f"IRC Server\nRequireAuth: false\n255,255,255\n"
            add_file(irc, "users.cfg", cfg)

        # ---------- ISPDaemon ----------
        elif tag == "ispSystem":
            home = root.find("folder[@name='home']")
            if home is not None and home.find("file[@name='ISP_About_Message.txt']") is None:
                add_file(home, "ISP_About_Message.txt", self._get_daemon_resource("ISPAbout.txt"))

        # ---------- LogoDaemon ----------
        elif tag == "LogoDaemon":
            if daemon_attrs and daemon_attrs.get('BodyText'):
                sysf = root.find("folder[@name='sys']")
                if sysf is not None:
                    add_file(sysf, "DisplayText.txt", daemon_attrs['BodyText'])

        # ---------- MedicalDatabase ----------
        elif tag == "MedicalDatabase":
            med = ensure_folder("Medical")
            people = self._load_people_from_xml()
            if people:
                for pid, person in people.items():
                    fname = f"{person['lastName'].lower()}_{person['firstName'].lower()}.rec"
                    if med.find(f"file[@name='{fname}']") is None:
                        add_file(med, fname, self._format_medical_record(person))
            else:
                # 降级样例
                for last, first, gender, dob, record in [
                    ("Smith", "John", "male", "1985-03-12", "Blood Type: O+\nAllergies: Penicillin"),
                    ("Doe", "Jane", "female", "1990-07-23", "Blood Type: A-\nAllergies: None"),
                ]:
                    fname = f"{last.lower()}_{first.lower()}.rec"
                    content = f"{first}\n-----------------\n{last}\n-----------------\n{gender}\n-----------------\n{dob}\n-----------------\n{record}"
                    add_file(med, fname, content)
            home = root.find("folder[@name='home']")
            if home is not None and home.find("file[@name='MedicalDatabaseInfo.txt']") is None:
                add_file(home, "MedicalDatabaseInfo.txt", self._get_daemon_resource("MedicalDatabaseInfo.txt"))

        # ---------- MessageBoard ----------
        elif tag == "MessageBoard":
            ib = ensure_folder("ImageBoard")
            ensure_folder("Threads", parent=ib)

        # ---------- MissionHubServer ----------
        elif tag == "MissionHubServer":
            hub = ensure_folder("ContractHub")
            contracts = ensure_folder("Contracts", parent=hub)
            ensure_folder("Listings", parent=contracts)
            ensure_folder("Archives", parent=contracts)
            ensure_folder("Users", parent=hub)
            add_file(hub, "settings.sys", "ThemeColor = 0,255,255\n")

        # ---------- MissionListingServer ----------
        elif tag == "MissionListingServer":
            msgb = ensure_folder("MsgBoard")
            ensure_folder("listings", parent=msgb)
            ensure_folder("closed", parent=msgb)
            add_file(msgb, "config.sys", "// Mission Listing Server Configuration\n")

        # ---------- PointClicker ----------
        elif tag == "PointClicker":
            pc = ensure_folder("PointClicker")
            saves = ensure_folder("Saves", parent=pc)
            add_file(pc, "config.ini", self._generate_binary_string(1000))
            add_file(pc, "IMPORTANT_README_DONT_CRASH.txt",
                     "IMPORTANT : NEVER DELETE OR RE-NAME \"config.ini\"\n IT IS SYSTEM CRITICAL! Removing it causes instant crash. DO NOT TEST THIS")
            # 为一些预设用户生成存档
            people = self._load_people_from_xml()
            preset_users = ["Mengsk", "Bit"] + [p['handle'] for p in list(people.values())[:5]]
            for i, user in enumerate(preset_users):
                is_super = user in ("Mengsk", "Bit")
                points = random.randint(0, 1000000) if is_super else random.randint(0, 10000)
                story = random.randint(0, 6)
                upgrades = [random.randint(0, 20) for _ in range(50)]
                save_str = f"{points}\n{story}\n" + ','.join(str(c) for c in upgrades)
                add_file(saves, f"{user}.pcsav", save_str)

        # ---------- UploadServerDaemon ----------
        elif tag == "UploadServerDaemon":
            folder_name = daemon_attrs.get('foldername', 'Drop') if daemon_attrs else 'Drop'
            up = ensure_folder(folder_name)
            ensure_folder("Uploads", parent=up)
            add_file(up, "Server_Message.txt", self._get_daemon_resource("UploadServerText.txt"))

        # ---------- WebServer / OnlineWebServer ----------
        elif tag in ("WebServer", "OnlineWebServerDaemon"):
            web = ensure_folder("web")
            if web.find("file[@name='index.html']") is None:
                html = self._get_daemon_resource("BaseImageWebPage.html")
                if html.startswith("[Missing"):
                    html = "<html><body><h1>Web Server</h1></body></html>"
                encoded_html = self.encode_hacknet_markers(html)
                add_file(web, "index.html", encoded_html)

        # ---------- WhitelistAuthenticatorDaemon ----------
        elif tag == "WhitelistAuthenticatorDaemon":
            wl = ensure_folder("Whitelist")
            if wl.find("file[@name='authenticator.dll']") is None:
                add_file(wl, "authenticator.dll", self._generate_binary_string(500))
            if wl.find("file[@name='list.txt']") is None:
                player = self.get_player_computer()
                admin_ip = player.get('ip') if player is not None else "127.0.0.1"
                add_file(wl, "list.txt", admin_ip)

    def createNewComputer(self):
        if self.xml_root is None:
            messagebox.showinfo(message="请先打开一个存档！")
            return

        win = tk.Toplevel(self.ui)
        win.title("新建节点")
        win.resizable(False, False)

        # IP
        tk.Label(win, text="IP 地址:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        ip_var = tk.StringVar(value=self._get_unused_ip())
        ip_frame = tk.Frame(win)
        ip_frame.grid(row=0, column=1, columnspan=2, sticky="w", padx=5, pady=2)
        ip_entry = tk.Entry(ip_frame, textvariable=ip_var, width=20)
        ip_entry.pack(side=tk.LEFT)
        tk.Button(ip_frame, text="随机", command=lambda: ip_var.set(self._get_unused_ip())).pack(side=tk.LEFT, padx=(2, 0))

        # 名称
        tk.Label(win, text="节点名称:").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        name_var = tk.StringVar(value="New Node")
        tk.Entry(win, textvariable=name_var, width=20).grid(row=1, column=1, sticky="w", padx=5, pady=2)

        # 类型
        tk.Label(win, text="节点类型:").grid(row=2, column=0, sticky="e", padx=5, pady=2)
        type_var = tk.IntVar(value=1)
        type_combo = tk.ttk.Combobox(win, textvariable=type_var, values=list(range(1, 6)), state="readonly", width=5)
        type_combo.grid(row=2, column=1, sticky="w", padx=5, pady=2)

        # 守护进程
        tk.Label(win, text="守护进程:").grid(row=3, column=0, sticky="e", padx=5, pady=2)
        daemon_var = tk.StringVar(value="无")
        daemon_combo = tk.ttk.Combobox(win, textvariable=daemon_var, values=list(DAEMON_DEFS.keys()), state="readonly", width=22)
        daemon_combo.grid(row=3, column=1, sticky="w", padx=5, pady=2)

        daemon_attrs = {}

        def on_daemon_change(*args):
            sel = daemon_var.get()
            if sel == "无":
                daemon_attrs.clear()
                return
            tag, attrs = DAEMON_DEFS[sel]
            if not attrs:
                daemon_attrs.clear()
                return
            win_height = 150 + len(attrs) * 30
            dlg = tk.Toplevel(win)
            dlg.title(f"设置 {sel} 属性")
            # dlg.geometry(f"300x{win_height}")
            dlg.resizable(False, False)
            dlg.grab_set()
            entries = {}
            for i, attr in enumerate(attrs):
                tk.Label(dlg, text=attr + ":").grid(row=i, column=0, sticky="e", padx=5, pady=2)
                var = tk.StringVar()
                tk.Entry(dlg, textvariable=var, width=20).grid(row=i, column=1, sticky="w", padx=5, pady=2)
                entries[attr] = var

            def confirm():
                for attr, var in entries.items():
                    if not var.get().strip():
                        messagebox.showwarning("错误", f"属性 '{attr}' 不能为空", parent=dlg)
                        return
                daemon_attrs.clear()
                for attr, var in entries.items():
                    daemon_attrs[attr] = var.get().strip()
                dlg.destroy()

            def on_dlg_close():
                daemon_var.set("无")
                daemon_attrs.clear()
                dlg.destroy()

            dlg.protocol("WM_DELETE_WINDOW", on_dlg_close)
            tk.Button(dlg, text="确定", command=confirm, width=10).grid(row=len(attrs), column=0, columnspan=2, pady=10)

        daemon_var.trace_add("write", on_daemon_change)

        # ID
        tk.Label(win, text="ID (可空):").grid(row=4, column=0, sticky="e", padx=5, pady=2)
        id_var = tk.StringVar()
        tk.Entry(win, textvariable=id_var, width=20).grid(row=4, column=1, sticky="w", padx=5, pady=2)

        # 坐标
        tk.Label(win, text="坐标 X:").grid(row=5, column=0, sticky="e", padx=5, pady=2)
        coord_frame = tk.Frame(win)
        coord_frame.grid(row=5, column=1, columnspan=4, sticky="w", padx=5, pady=2)
        loc_x_var = tk.StringVar(value=str(round(random.random(), 6)))
        tk.Entry(coord_frame, textvariable=loc_x_var, width=8).pack(side=tk.LEFT)
        tk.Label(coord_frame, text="Y:").pack(side=tk.LEFT, padx=(4, 0))
        loc_y_var = tk.StringVar(value=str(round(random.random(), 6)))
        tk.Entry(coord_frame, textvariable=loc_y_var, width=8).pack(side=tk.LEFT, padx=(2, 0))
        tk.Button(coord_frame, text="随机坐标",
                  command=lambda: [loc_x_var.set(str(round(random.random(), 6))),
                                   loc_y_var.set(str(round(random.random(), 6)))]).pack(side=tk.LEFT, padx=(4, 0))

        # 管理员密码
        tk.Label(win, text="管理员密码:").grid(row=6, column=0, sticky="e", padx=5, pady=2)
        admin_pass_var = tk.StringVar(value=''.join(random.choices(string.ascii_letters + string.digits, k=8)))
        tk.Entry(win, textvariable=admin_pass_var, width=20).grid(row=6, column=1, sticky="w", padx=5, pady=2)

        # 系统主题（仅使用已验证的数据）
        tk.Label(win, text="系统主题:").grid(row=7, column=0, sticky="e", padx=5, pady=2)
        theme_var = tk.StringVar(value=DEFAULT_THEME)
        theme_combo = tk.ttk.Combobox(win, textvariable=theme_var,
                                       values=list(THEME_DATA.keys()), state="readonly", width=22)
        theme_combo.grid(row=7, column=1, sticky="w", padx=5, pady=2)

        # 安全等级 + 高级设置
        tk.Label(win, text="安全等级:").grid(row=8, column=0, sticky="e", padx=5, pady=2)
        sec_var = tk.IntVar(value=2)
        sec_frame = tk.Frame(win)
        sec_frame.grid(row=8, column=1, columnspan=2, sticky="w", padx=5, pady=2)
        sec_combo = tk.ttk.Combobox(sec_frame, textvariable=sec_var, values=list(range(1, 6)), state="readonly", width=5)
        sec_combo.pack(side=tk.LEFT)
        adv_result = {"ports": [], "portsToCrack": "", "firewall_enabled": False,
                      "firewall_pass": "", "traceTime": "", "proxyTime": ""}

        def update_adv_defaults(*args):
            sec = sec_var.get()
            adv_result["ports"] = [22, 21, 25, 80][:min(4, sec)]
            adv_result["portsToCrack"] = str(sec - 1 if sec < 5 else sec - 2)
            adv_result["firewall_enabled"] = sec >= 5
            adv_result["firewall_pass"] = ''.join(
                random.choices(string.ascii_letters + string.digits, k=8)
            ) if sec >= 5 else ""
            adv_result["traceTime"] = str(max(10 - sec, 3) * 15) if sec >= 4 else "-1"
            adv_result["proxyTime"] = "-1"

        update_adv_defaults()
        sec_var.trace_add("write", update_adv_defaults)
        tk.Button(sec_frame, text="高级设置",
                  command=lambda: self._open_advanced_settings(win, adv_result)).pack(side=tk.LEFT, padx=(2, 0))

        # 生成按钮
        def do_generate():
            ip = ip_var.get().strip()
            name = name_var.get().strip()
            if not name:
                messagebox.showwarning("错误", "节点名称不能为空")
                return
            existing_ips = {comp.get('ip') for comp in self.xml_root.findall('.//computer')}
            if ip in existing_ips:
                messagebox.showwarning("错误", f"IP {ip} 已被使用")
                return
            try:
                x = float(loc_x_var.get())
                y = float(loc_y_var.get())
                if not (0 <= x <= 1 and 0 <= y <= 1):
                    raise ValueError
            except:
                messagebox.showwarning("错误", "坐标必须在0~1之间")
                return
            admin_pass = admin_pass_var.get().strip()
            if not admin_pass:
                admin_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            if not adv_result["ports"]:
                messagebox.showwarning("错误", "至少需要选择一个开放端口")
                return
            try:
                int(adv_result["portsToCrack"])
            except:
                messagebox.showwarning("错误", "骇入需要端口数必须为数字")
                return
            if adv_result["firewall_enabled"] and not adv_result["firewall_pass"].strip():
                messagebox.showwarning("错误", "防火墙密码不能为空")
                return
            try:
                if adv_result["traceTime"]:
                    float(adv_result["traceTime"])
            except:
                messagebox.showwarning("错误", "追踪时间必须为数字")
                return
            try:
                if adv_result["proxyTime"]:
                    float(adv_result["proxyTime"])
            except:
                messagebox.showwarning("错误", "代理时间必须为数字")
                return

            comp = self._build_computer_element(
                name=name, ip=ip, sec_level=sec_var.get(), comp_type=type_var.get(),
                admin_pass=admin_pass, gen_random_fs=True,
                id_name=id_var.get().strip() or None,
                loc_x=x, loc_y=y,
                daemon_key=daemon_var.get(), daemon_attrs=daemon_attrs,
                adv_result=adv_result,
                theme_name=theme_var.get()
            )
            self.xml_root.find('.//network').append(comp)
            vis = self.xml_root.find('.//visible')
            if vis is not None:
                cur = vis.text.strip() if vis.text else ''
                vis.text = (cur + ' ' + str(self.computer_num)).strip()
            self.computer_num += 1
            self.showComputer()
            win.destroy()
            messagebox.showinfo("成功", f"节点 {name} 创建成功。\n请手动保存存档。")

        btn_frame = tk.Frame(win)
        btn_frame.grid(row=9, column=0, columnspan=5, pady=15)
        tk.Button(btn_frame, text="生成节点", command=do_generate, width=15).pack()

    def _open_advanced_settings(self, parent, result_dict):
        adv = Toplevel(parent)
        adv.title("高级安全设置")
        adv.geometry("450x400")
        adv.resizable(False, False)
        adv.grab_set()

        Label(adv, text="开放端口 (至少选一个):").grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        port_vars = {}
        row = 1
        col = 0
        for port in ALL_PORTS:
            var = BooleanVar(value=(port in result_dict["ports"]))
            port_vars[port] = var
            cb = Checkbutton(adv, text=f"{port} ({PORT_NAMES.get(port,'')})", variable=var)
            cb.grid(row=row, column=col, sticky="w", padx=10)
            col += 1
            if col > 1:
                col = 0
                row += 1

        row += 1
        Label(adv, text="骇入需要端口数:").grid(row=row, column=0, sticky="e", padx=10, pady=5)
        ports_crack_var = StringVar(value=result_dict["portsToCrack"])
        Entry(adv, textvariable=ports_crack_var, width=10).grid(row=row, column=1, sticky="w", padx=10)

        row += 1
        firewall_var = BooleanVar(value=result_dict["firewall_enabled"])
        Checkbutton(adv, text="启用防火墙", variable=firewall_var, command=lambda: toggle_fw()).grid(row=row, column=0, sticky="w", padx=10)
        fw_pass_var = StringVar(value=result_dict["firewall_pass"])
        fw_entry = Entry(adv, textvariable=fw_pass_var, width=15)
        fw_entry.grid(row=row, column=1, sticky="w", padx=10)
        if not firewall_var.get():
            fw_entry.config(state="disabled")

        def toggle_fw():
            if firewall_var.get():
                fw_entry.config(state="normal")
            else:
                fw_entry.config(state="disabled")
                fw_pass_var.set("")

        row += 1
        Label(adv, text="追踪时间 (秒):").grid(row=row, column=0, sticky="e", padx=10, pady=5)
        trace_var = StringVar(value=result_dict["traceTime"])
        Entry(adv, textvariable=trace_var, width=10).grid(row=row, column=1, sticky="w", padx=10)

        row += 1
        Label(adv, text="代理时间 (秒):").grid(row=row, column=0, sticky="e", padx=10, pady=5)
        proxy_var = StringVar(value=result_dict["proxyTime"])
        Entry(adv, textvariable=proxy_var, width=10).grid(row=row, column=1, sticky="w", padx=10)

        def save_adv():
            selected_ports = [p for p, v in port_vars.items() if v.get()]
            if not selected_ports:
                messagebox.showwarning("错误", "至少需要选择一个开放端口", parent=adv)
                return
            try:
                int(ports_crack_var.get())
            except:
                messagebox.showwarning("错误", "骇入需要端口数必须为数字", parent=adv)
                return
            if firewall_var.get() and not fw_pass_var.get().strip():
                messagebox.showwarning("错误", "防火墙密码不能为空", parent=adv)
                return
            try:
                if trace_var.get():
                    float(trace_var.get())
            except:
                messagebox.showwarning("错误", "追踪时间必须为数字", parent=adv)
                return
            try:
                if proxy_var.get():
                    float(proxy_var.get())
            except:
                messagebox.showwarning("错误", "代理时间必须为数字", parent=adv)
                return

            result_dict["ports"] = selected_ports
            result_dict["portsToCrack"] = ports_crack_var.get()
            result_dict["firewall_enabled"] = firewall_var.get()
            result_dict["firewall_pass"] = fw_pass_var.get()
            result_dict["traceTime"] = trace_var.get()
            result_dict["proxyTime"] = proxy_var.get()
            adv.destroy()

        tk.Button(adv, text="保存", command=save_adv, width=10).grid(row=row+1, column=0, columnspan=2, pady=15)

    def _build_computer_element(self, name, ip, sec_level, comp_type, admin_pass,
                                gen_random_fs=True, id_name=None, loc_x=None, loc_y=None,
                                daemon_key="无", daemon_attrs=None, adv_result=None,
                                theme_name=DEFAULT_THEME):
        if loc_x is None:
            loc_x = random.random()
        if loc_y is None:
            loc_y = random.random()

        if adv_result is None:
            adv_result = {
                "ports": [22,21,25,80][:min(4, sec_level)],
                "portsToCrack": str(sec_level-1 if sec_level<5 else sec_level-2),
                "firewall_enabled": sec_level>=5,
                "firewall_pass": ''.join(random.choices(string.ascii_letters+string.digits, k=8)) if sec_level>=5 else "",
                "traceTime": str(max(10-sec_level,3)*15) if sec_level>=4 else "-1",
                "proxyTime": "-1"
            }

        # 构建属性字典：基础属性 + id（仅当非空）+ 自定义标记
        comp_attrs = {
            'name': name,
            'ip': ip,
            'type': str(comp_type),
            'spec': 'none',
            'editor': 'true'          # 自定义节点标记，游戏忽略
        }
        if id_name:                    # 只有非空时才添加 id 属性
            comp_attrs['id'] = id_name

        comp = ET.Element('computer', comp_attrs)
        comp.text = '\n'
        comp.tail = '\n'

        ET.SubElement(comp, 'location', {'x': str(loc_x), 'y': str(loc_y)}).tail = '\n'
        ET.SubElement(comp, 'security', {
            'level': str(sec_level),
            'traceTime': adv_result["traceTime"],
            'portsToCrack': adv_result["portsToCrack"],
            'adminIP': '',
            'proxyTime': adv_result["proxyTime"]
        }).tail = '\n'
        ET.SubElement(comp, 'admin', {'type': 'basic', 'resetPass': 'false', 'isSuper': 'false'}).tail = '\n'

        links = ET.SubElement(comp, 'links')
        links.tail = '\n'

        if adv_result["firewall_enabled"]:
            ET.SubElement(comp, 'firewall', {
                'additionalDelay': '0',
                'complexity': str(max(0, sec_level-5)),
                'solution': adv_result["firewall_pass"]
            }).tail = '\n'

        ports = ET.SubElement(comp, 'portsOpen')
        ports.text = ' '.join(map(str, adv_result["ports"]))
        ports.tail = '\n'

        users = ET.SubElement(comp, 'users')
        users.text = '\n'
        ET.SubElement(users, 'user', {'known': 'True', 'name': 'admin', 'pass': admin_pass, 'type': '1'}).tail = '\n'
        users.tail = '\n'

        # 守护进程标签（必需，否则卡死）
        daemons_elem = ET.SubElement(comp, 'daemons')
        if daemon_key != "无":
            daemons_elem.text = '\n'
            tag, attrs = DAEMON_DEFS[daemon_key]
            elem = ET.SubElement(daemons_elem, tag)
            if daemon_attrs:
                for attr, val in daemon_attrs.items():
                    elem.set(attr, val)
            elem.tail = '\n'
        else:
            daemons_elem.text = '\n'
        daemons_elem.tail = '\n'

        # 文件系统
        fs_elem = ET.SubElement(comp, 'filesystem')
        fs_elem.text = '\n'
        fs_elem.tail = '\n'

        root = ET.SubElement(fs_elem, 'folder', {'name': '/'})
        root.text = '\n'
        root.tail = '\n'

        for folder_name in ['home', 'log', 'bin', 'sys']:
            folder = ET.SubElement(root, 'folder', {'name': folder_name})
            folder.text = '\n'
            folder.tail = '\n'
            if folder_name == 'sys':
                xserver_data = THEME_DATA.get(theme_name, THEME_DATA[DEFAULT_THEME])
                f = ET.SubElement(folder, 'file', {'name': 'x-server.sys'})
                f.text = xserver_data
                f.tail = '\n'
                for sys_file in ['os-config.sys', 'bootcfg.dll', 'netcfgx.dll']:
                    correct_bin = self._generate_binary_string(500)
                    f2 = ET.SubElement(folder, 'file', {'name': sys_file})
                    f2.text = correct_bin
                    f2.tail = '\n'

        if daemon_key != "无":
            self._add_daemon_filesystems(comp, daemon_key, daemon_attrs, admin_pass)

        fs_elem.tail = '\n'
        return comp

if __name__ == "__main__":
    app = Win(Controller())
    app.mainloop()
