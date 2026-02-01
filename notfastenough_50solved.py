#!/usr/bin/env python3
import re
import ast
import sys
from pwn import *

HOST = 'scripting.ctf.pascalctf.it'
PORT = 6004

# Tắt log để tối đa tốc độ
context.log_level = 'error'

# ================== CACHED CONSTANTS & REGEX ==================
# Pre-compile regex để tăng tốc độ xử lý chuỗi
RE_SERIAL = re.compile(r"Serial Number: (\w+)")
RE_BATT   = re.compile(r"Batteries: (\d+)")
RE_PORTS  = re.compile(r"Ports: (.+)")
RE_IND    = re.compile(r"(?:Label|Indicators): (.+)")

VOWELS = set("AEIOU")

# Sử dụng Tuple thay vì List cho dữ liệu tĩnh để truy xuất nhanh hơn
KEYPAD_COLS = (
    ('Ϙ','Ѧ','ƛ','Ϟ','Ѭ','ϗ','Ͽ'),
    ('Ӭ','Ϙ','Ͽ','Ҩ','☆','ϗ','¿'),
    ('©','Ѽ','Ҩ','Җ','Ԇ','ƛ','☆'),
    ('б','¶','ƀ','Ѭ','Җ','¿','ټ'),
    ('ψ','ټ','ƀ','Ͼ','¶','Ѯ','★'),
    ('б','Ӭ','҂','æ','ψ','Ҋ','Ω'),
)

MORSE_FREQ = {
    "shell":"3.505","halls":"3.515","slick":"3.522","trick":"3.532","boxes":"3.535",
    "leaks":"3.542","strobe":"3.545","bistro":"3.552","flick":"3.555","bombs":"3.565",
    "break":"3.572","brick":"3.575","steak":"3.582","sting":"3.592","vector":"3.595",
    "beats":"3.600"
}

COMPLICATED_LOGIC = {
    (0,0,0,0):'C', (0,0,1,0):'C', (0,0,0,1):'D', (0,0,1,1):'B',
    (0,1,0,0):'S', (0,1,1,0):'D', (0,1,0,1):'P', (0,1,1,1):'P',
    (1,0,0,0):'S', (1,0,1,0):'C', (1,0,0,1):'B', (1,0,1,1):'B',
    (1,1,0,0):'S', (1,1,1,0):'P', (1,1,0,1):'S', (1,1,1,1):'D'
}

WIRE_SEQ = {
    'red':   {1:'C',2:'B',3:'A',4:'AC',5:'B',6:'AC',7:'ABC',8:'AB',9:'B'},
    'blue':  {1:'B',2:'AC',3:'B',4:'A',5:'B',6:'BC',7:'C',8:'AC',9:'A'},
    'black': {1:'ABC',2:'AC',3:'B',4:'AC',5:'B',6:'BC',7:'AB',8:'C',9:'C'}
}

PASSWORDS = (
    "about","after","again","below","could","every","first","found","great","house",
    "large","learn","never","other","place","plant","point","right","small","sound",
    "spell","still","study","their","there","these","thing","think","three","water",
    "where","which","world","would","write"
)

# ================== SOLVER CLASS ==================

class BombSolver:
    __slots__ = (
        'r', 'serial', 'batteries', 'ports', 'indicators',
        'serial_odd', 'serial_vowel', 'parallel',
        'memory_history', 'wire_seq_counts'
    )

    def __init__(self, connection):
        self.r = connection
        self.serial = ""
        self.batteries = 0
        self.ports = ()
        self.indicators = ()
        self.serial_odd = False
        self.serial_vowel = False
        self.parallel = False
        self.memory_history = [] 
        self.wire_seq_counts = {'red': 0, 'blue': 0, 'black': 0}

    def parse_header(self):
        print(" [*] Đang phân tích thông số (Fast Mode)...")
        try:
            header_data = self.r.recvuntil(b"==================================================", timeout=5).decode()
            
            if m := RE_SERIAL.search(header_data):
                self.serial = m.group(1)
                self.serial_odd = int(self.serial[-1]) & 1
                self.serial_vowel = any(c in VOWELS for c in self.serial.upper())
            
            if m := RE_BATT.search(header_data):
                self.batteries = int(m.group(1))
                
            if m := RE_PORTS.search(header_data):
                self.ports = tuple(p.strip().lower() for p in m.group(1).split(','))
                self.parallel = 'parallel' in self.ports
                
            if m := RE_IND.search(header_data):
                self.indicators = tuple(i.strip().upper() for i in m.group(1).split(','))
                
            print(f" [+] Serial: {self.serial} | Batt: {self.batteries}")
        except Exception as e:
            print(f" [!] Lỗi header: {e}")

    # --- LOGIC MODULES (Giữ nguyên tối ưu + Thêm lại Mazes/Knobs) ---

    def solve_wires(self, d):
        colors = d['colors']
        n = len(colors)
        last = colors[-1].lower()
        # Đếm nhanh bằng list comprehension/count đã tối ưu sẵn trong C của Python
        # Lưu ý: server gửi 'Red', 'Blue' nên cần lower() hoặc đếm chính xác
        # Để an toàn và nhanh, ta normalize 1 lần
        c_norm = [x.lower() for x in colors]
        rc = c_norm.count('red')
        bc = c_norm.count('blue')
        yc = c_norm.count('yellow')
        wc = c_norm.count('white')
        
        if n == 3:
            if rc == 0: return 2
            if last == 'white': return 3
            if bc > 1: return n - c_norm[::-1].index('blue')
            return 3
        elif n == 4:
            if rc > 1 and self.serial_odd: return n - c_norm[::-1].index('red')
            if last == 'yellow' and rc == 0: return 1
            if bc == 1: return 1
            if yc > 1: return 4
            return 2
        elif n == 5:
            if last == 'black' and self.serial_odd: return 4
            if rc == 1 and yc > 1: return 1
            if 'black' not in c_norm: return 2
            return 1
        elif n == 6:
            if yc == 0 and self.serial_odd: return 3
            if yc == 1 and wc > 1: return 4
            if rc == 0: return 6
            return 4
        return 1

    def solve_button(self, d):
        color = d.get('color','').lower()
        label = d.get('text', d.get('label','')).lower()
        strip = d.get('color_strip','').lower()
        
        # Logic 1 dòng (Short-circuit evaluation)
        should_press = (
            (color=='blue' and label=='abort') or
            (self.batteries > 1 and label=='detonate') or
            (self.batteries > 2 and 'FRK' in self.indicators) or
            (color=='red' and label=='hold')
        )
        # Sửa logic: Các điều kiện trên là HOLD, ngược lại là PRESS?
        # Check lại manual:
        # 1. Blue & Abort -> Hold
        # 2. >1 Batt & Detonate -> Press (Ngắt ngay)
        # 3. White & CAR -> Hold
        # 4. >2 Batt & FRK -> Press (Ngắt ngay)
        # 5. Yellow -> Hold
        # 6. Red & Hold -> Press (Ngắt ngay)
        # 7. Else -> Hold
        
        # Viết lại logic cho rõ ràng và chính xác theo manual
        action = "hold"
        if color=='blue' and label=='abort': action="hold"
        elif self.batteries>1 and label=='detonate': action="press"
        elif color=='white' and 'CAR' in self.indicators: action="hold"
        elif self.batteries>2 and 'FRK' in self.indicators: action="press"
        elif color=='yellow': action="hold"
        elif color=='red' and label=='hold': action="press"
        else: action="hold"

        if action == "press": return "press", 0
        
        # Logic thả nút
        return "hold", {'blue':4, 'white':1, 'yellow':5}.get(strip, 1)

    def solve_keypads(self, d):
        syms = d['symbols']
        s_set = set(syms)
        for col in KEYPAD_COLS:
            # Đếm số phần tử trùng
            common = [s for s in col if s in s_set]
            if len(common) >= 3: # Fallback 3/4
                # Phải trả về thứ tự 1-4 dựa trên vị trí trong `syms`
                # common đã được sort theo thứ tự xuất hiện trong Cột (do list comprehension duyệt col)
                # Cần map ngược lại index của symbol trong input đề bài
                return " ".join(str(syms.index(c) + 1) for c in common)
        return "1 2 3 4"

    def solve_simon(self, d):
        colors = [c.lower() for c in d['colors']]
        strikes = d.get('strikes', 0)
        
        # Pre-defined maps để tránh tạo dict mỗi lần gọi
        if self.serial_vowel:
            maps = (
                {'red':'blue', 'blue':'red', 'green':'yellow', 'yellow':'green'},
                {'red':'yellow', 'blue':'green', 'green':'blue', 'yellow':'red'},
                {'red':'green', 'blue':'red', 'green':'yellow', 'yellow':'blue'}
            )
        else:
            maps = (
                {'red':'blue', 'blue':'yellow', 'green':'green', 'yellow':'red'},
                {'red':'red', 'blue':'blue', 'green':'yellow', 'yellow':'green'},
                {'red':'yellow', 'blue':'green', 'green':'blue', 'yellow':'red'}
            )
        
        m = maps[min(strikes, 2)]
        return " ".join(m[c] for c in colors)

    def solve_morse(self, d):
        return MORSE_FREQ.get(d.get('word',''), "3.505")

    def solve_complicated(self, d):
        res = []
        for i in range(d['amount']):
            c = d['colors'][i].lower()
            mask = (
                'red' in c,
                'blue' in c,
                d['stars'][i],
                d['leds'][i]
            )
            act = COMPLICATED_LOGIC[mask]
            
            if act == 'C': res.append('cut')
            elif act == 'D': res.append('skip')
            elif act == 'S': res.append('cut' if not self.serial_odd else 'skip')
            elif act == 'P': res.append('cut' if self.parallel else 'skip')
            elif act == 'B': res.append('cut' if self.batteries >= 2 else 'skip')
        return res

    def solve_wire_sequence(self, d):
        res = []
        for w in d['wires']:
            c = w['color'].lower()
            t = w['target'].upper()
            self.wire_seq_counts[c] += 1
            # Dictionary lookup cực nhanh
            valid_targets = WIRE_SEQ[c].get(self.wire_seq_counts[c], '')
            res.append('cut' if t in valid_targets else 'skip')
        return res

    def solve_passwords(self, d):
        opts = d['letters'] # ['abc', 'def', ...]
        # Duyệt qua 35 từ, từ nào khớp thì return ngay
        for w in PASSWORDS:
            # Kiểm tra nhanh: ký tự đầu tiên của từ có trong options[0] không?
            if w[0].upper() not in opts[0].upper(): continue
            
            # Kiểm tra full
            if all(w[i].upper() in opts[i].upper() for i in range(5)):
                return w
        return PASSWORDS[0]

    def solve_memory(self, d):
        s = d['stage']
        disp = int(d['display'])
        mh = self.memory_history
        pos = 0; lbl = 0

        if s == 1:
            pos = (2, 2, 3, 4)[disp-1]
        elif s == 2:
            if disp == 1: pos=0; lbl=4
            elif disp in (2, 4): pos=mh[0]['pos']
            else: pos=1
        elif s == 3:
            if disp == 1: lbl=mh[1]['lbl']
            elif disp == 2: lbl=mh[0]['lbl']
            elif disp == 3: pos=3
            else: lbl=4
        elif s == 4:
            if disp == 1: pos=mh[0]['pos']
            elif disp == 2: pos=1
            elif disp in (3, 4): pos=mh[1]['pos']
        elif s == 5:
            lbl = mh[(0, 1, 3, 2)[disp-1]]['lbl']

        mh.append({'pos': pos, 'lbl': lbl})
        return str(pos or lbl)

    
    def solve_wof(self, d):

        return self.solve_wof_v3(d) 

    def solve_wof_v3(self, data):
        # Copy lại logic WOF từ bản v3
        display = data['display']
        # Map nhanh
        step1 = {"YES": 2, "FIRST": 1, "DISPLAY": 5, "OKAY": 1, "SAYS": 5, "NOTHING": 2, "BLANK": 3, "NO": 5, "LED": 2, "LEAD": 5, "READ": 3, "RED": 3, "REED": 4, "LEED": 4, "HOLD ON": 5, "YOU": 3, "YOU ARE": 5, "YOUR": 3, "YOU'RE": 3, "UR": 0, "THERE": 5, "THEY'RE": 4, "THEIR": 3, "THEY ARE": 2, "SEE": 5, "CEE": 5, "": 4}
        pos_map = {1:0, 2:1, 3:2, 4:3, 5:4, 6:5}
        target_idx = pos_map.get(step1.get(display, 5), 5) 
        buttons = data['buttons']
        label = buttons[target_idx]

        return buttons[0] 

    def solve_mazes(self, d):
        return "UP"

    def solve_knobs(self, d):
        return "UP"

    # ---------------- RUN LOOP ----------------
    def run(self):
        self.parse_header()
        self.r.sendlineafter(b"(press Enter):", b"1")

        for i in range(1, 101):
            try:
                self.r.recvuntil(b"Module: ")
                name = self.r.recvline().strip().decode()
                self.r.recvuntil(b"Data: ")

                data = ast.literal_eval(self.r.recvline().decode())

                if name == "Wires":
                    ans = self.solve_wires(data)
                    self.r.sendlineafter(b":", str(ans).encode())
                elif name == "Complicated Wires":
                    for idx, a in enumerate(self.solve_complicated(data)):
                        self.r.sendlineafter(f"Wire {idx+1}:".encode(), a.encode())
                elif name == "Keypads":
                    self.r.sendlineafter(b":", self.solve_keypads(data).encode())
                elif name == "Button":
                    act, rel = self.solve_button(data)
                    choice = b"1" if act == "press" else b"2"
                    self.r.sendlineafter(b"(1 or 2):", choice)
                    if act == "hold":
                        self.r.sendlineafter(b"(0-9):", str(rel).encode())
                elif name == "Simon Says":
                    self.r.sendlineafter(b":", self.solve_simon(data).encode())
                elif name == "Who's on First":
                    pass 
                elif name == "Memory":
                    self.r.sendlineafter(b":", self.solve_memory(data).encode())
                elif name == "Wire Sequences":
                    self.r.sendlineafter(b":", str(self.solve_wire_sequence(data)).encode())
                elif name == "Passwords":
                    self.r.sendlineafter(b":", self.solve_passwords(data).encode())
                elif name == "Morse Code":
                    self.r.sendlineafter(b":", self.solve_morse(data).encode())
                elif name == "Knobs":
                    self.r.sendlineafter(b":", self.solve_knobs(data).encode())
                elif name == "Mazes":
                    self.r.sendlineafter(b":", self.solve_mazes(data).encode())
                else:
                    self.r.sendline(b"1")

                if i < 100:
                    self.r.sendlineafter(b"(press Enter):", str(i+1).encode())

            except Exception as e:
                print(f"[!] Err {i}: {e}")
                break
        
        self.r.interactive()

if __name__ == "__main__":
    conn = remote(HOST, PORT)
    solver = BombSolver(conn)
    solver.run()