#!/usr/bin/env python3
import re
import ast
import sys
from pwn import *

# Cấu hình kết nối
HOST = 'scripting.ctf.pascalctf.it'
PORT = 6004

# TẮT LOG ĐỂ TĂNG TỐC ĐỘ
context.log_level = 'error'

class BombSolver:
    def __init__(self, connection):
        self.r = connection
        self.serial = ""
        self.batteries = 0
        self.ports = []
        self.indicators = []
        self.serial_odd = False
        self.serial_vowel = False
        self.parallel = False
        self.memory_history = [] 
        self.wire_seq_counts = {'red': 0, 'blue': 0, 'black': 0}

    def parse_header(self):
        print(" [*] Đang phân tích thông số...")
        try:
            header_data = self.r.recvuntil(b"==================================================", timeout=5).decode()
            s_match = re.search(r"Serial Number: (\w+)", header_data)
            if s_match:
                self.serial = s_match.group(1)
                self.serial_odd = int(self.serial[-1]) % 2 != 0
                self.serial_vowel = any(c in "AEIOU" for c in self.serial.upper())
            b_match = re.search(r"Batteries: (\d+)", header_data)
            if b_match: self.batteries = int(b_match.group(1))
            p_match = re.search(r"Ports: (.+)", header_data)
            if p_match:
                self.ports = [p.strip().lower() for p in p_match.group(1).split(',')]
                self.parallel = 'parallel' in self.ports
            i_match = re.search(r"(?:Label|Indicators): (.+)", header_data)
            if i_match: self.indicators = [i.strip().upper() for i in i_match.group(1).split(',')]
            print(f" [+] Serial: {self.serial} | Batt: {self.batteries}")
        except Exception as e: print(f" [!] Lỗi header: {e}")

    def solve_wires(self, data):
        colors = [c.lower() for c in data['colors']]
        count = len(colors)
        if count == 3:
            if 'red' not in colors: return 2
            if colors[-1] == 'white': return 3
            if colors.count('blue') > 1: return len(colors) - colors[::-1].index('blue')
            return 3
        elif count == 4:
            if colors.count('red') > 1 and self.serial_odd: return len(colors) - colors[::-1].index('red')
            if colors[-1] == 'yellow' and 'red' not in colors: return 1
            if colors.count('blue') == 1: return 1
            if colors.count('yellow') > 1: return 4
            return 2
        elif count == 5:
            if colors[-1] == 'black' and self.serial_odd: return 4
            if colors.count('red') == 1 and colors.count('yellow') > 1: return 1
            if 'black' not in colors: return 2
            return 1
        elif count == 6:
            if 'yellow' not in colors and self.serial_odd: return 3
            if colors.count('yellow') == 1 and colors.count('white') > 1: return 4
            if 'red' not in colors: return 6
            return 4
        return 1

    def solve_button(self, data):
        color = data.get('color', '').lower()
        label = data.get('text', data.get('label', '')).lower()
        strip = data.get('color_strip', '').lower()
        action = "hold"
        if color == 'blue' and label == 'abort': action = "hold"
        elif self.batteries > 1 and label == 'detonate': action = "press"
        elif color == 'white' and 'CAR' in self.indicators: action = "hold"
        elif self.batteries > 2 and 'FRK' in self.indicators: action = "press"
        elif color == 'yellow': action = "hold"
        elif color == 'red' and label == 'hold': action = "press"
        else: action = "hold"
        
        release_digit = 1
        if action == "hold":
            if strip == 'blue': release_digit = 4
            elif strip == 'white': release_digit = 1
            elif strip == 'yellow': release_digit = 5
            else: release_digit = 1
        return action, release_digit

    def solve_keypads(self, data):
        columns = [
            ['Ϙ', 'Ѧ', 'ƛ', 'Ϟ', 'Ѭ', 'ϗ', 'Ͽ'],
            ['Ӭ', 'Ϙ', 'Ͽ', 'Ҩ', '☆', 'ϗ', '¿'],
            ['©', 'Ѽ', 'Ҩ', 'Җ', 'Ԇ', 'ƛ', '☆'],
            ['б', '¶', 'ƀ', 'Ѭ', 'Җ', '¿', 'ټ'],
            ['ψ', 'ټ', 'ƀ', 'Ͼ', '¶', 'Ѯ', '★'],
            ['б', 'Ӭ', '҂', 'æ', 'ψ', 'Ҋ', 'Ω']
        ]
        symbols = data['symbols']
        for col in columns:
            matches = [s for s in symbols if s in col]
            if len(matches) >= 3:
                ordered = sorted(matches, key=lambda x: col.index(x))
                return " ".join([str(symbols.index(s) + 1) for s in ordered])
        return "1 2 3 4"

    def solve_simon(self, data):
        flash_colors = [c.lower() for c in data['colors']]
        strikes = data.get('strikes', 0)
        if self.serial_vowel:
            mapping = {
                0: {'red': 'blue', 'blue': 'red', 'green': 'yellow', 'yellow': 'green'},
                1: {'red': 'yellow', 'blue': 'green', 'green': 'blue', 'yellow': 'red'},
                2: {'red': 'green', 'blue': 'red', 'green': 'yellow', 'yellow': 'blue'}
            }
        else:
            mapping = {
                0: {'red': 'blue', 'blue': 'yellow', 'green': 'green', 'yellow': 'red'},
                1: {'red': 'red', 'blue': 'blue', 'green': 'yellow', 'yellow': 'green'},
                2: {'red': 'yellow', 'blue': 'green', 'green': 'blue', 'yellow': 'red'}
            }
        current_map = mapping.get(strikes, mapping[0])
        return " ".join([current_map[c] for c in flash_colors])

    def solve_wof(self, data):
        display = data['display']
        step1 = {"YES": 2, "FIRST": 1, "DISPLAY": 5, "OKAY": 1, "SAYS": 5, "NOTHING": 2, "BLANK": 3, "NO": 5, "LED": 2, "LEAD": 5, "READ": 3, "RED": 3, "REED": 4, "LEED": 4, "HOLD ON": 5, "YOU": 3, "YOU ARE": 5, "YOUR": 3, "YOU'RE": 3, "UR": 0, "THERE": 5, "THEY'RE": 4, "THEIR": 3, "THEY ARE": 2, "SEE": 5, "CEE": 5, "": 4}
        pos_map = {1:0, 2:1, 3:2, 4:3, 5:4, 6:5}
        target_idx = pos_map.get(step1.get(display, 5), 5) 
        buttons = data['buttons']
        label_to_read = buttons[target_idx]
        priorities = {
            "READY": "YES, OKAY, WHAT, MIDDLE, LEFT, PRESS, RIGHT, BLANK, READY, NO, FIRST, UHHH, NOTHING, WAIT",
            "FIRST": "LEFT, OKAY, YES, MIDDLE, NO, RIGHT, NOTHING, UHHH, WAIT, READY, BLANK, WHAT, PRESS, FIRST",
            "NO": "BLANK, UHHH, WAIT, FIRST, WHAT, READY, RIGHT, YES, NOTHING, LEFT, PRESS, OKAY, NO, MIDDLE",
            "BLANK": "WAIT, RIGHT, OKAY, MIDDLE, BLANK, PRESS, READY, NOTHING, NO, WHAT, LEFT, UHHH, YES, FIRST",
            "NOTHING": "UHHH, RIGHT, OKAY, MIDDLE, YES, BLANK, NO, PRESS, LEFT, WHAT, WAIT, FIRST, NOTHING, READY",
            "YES": "OKAY, RIGHT, UHHH, MIDDLE, FIRST, WHAT, PRESS, READY, NOTHING, YES, LEFT, BLANK, NO, WAIT",
            "WHAT": "UHHH, WHAT, LEFT, NOTHING, READY, BLANK, MIDDLE, NO, OKAY, FIRST, WAIT, YES, PRESS, RIGHT",
            "UHHH": "READY, NOTHING, LEFT, WHAT, OKAY, YES, RIGHT, NO, PRESS, BLANK, UHHH, MIDDLE, WAIT, FIRST",
            "LEFT": "RIGHT, LEFT, FIRST, NO, MIDDLE, YES, BLANK, WHAT, UHHH, WAIT, PRESS, READY, OKAY, NOTHING",
            "RIGHT": "YES, NOTHING, READY, PRESS, NO, WAIT, WHAT, RIGHT, MIDDLE, LEFT, UHHH, BLANK, OKAY, FIRST",
            "MIDDLE": "BLANK, READY, OKAY, WHAT, NOTHING, PRESS, NO, WAIT, LEFT, MIDDLE, RIGHT, FIRST, UHHH, YES",
            "OKAY": "MIDDLE, NO, FIRST, YES, UHHH, NOTHING, WAIT, OKAY, LEFT, READY, BLANK, PRESS, WHAT, RIGHT",
            "WAIT": "UHHH, NO, BLANK, OKAY, YES, LEFT, FIRST, PRESS, WHAT, WAIT, NOTHING, READY, RIGHT, MIDDLE",
            "PRESS": "RIGHT, MIDDLE, YES, READY, PRESS, OKAY, NOTHING, UHHH, BLANK, LEFT, FIRST, WHAT, NO, WAIT",
            "YOU": "SURE, YOU ARE, YOUR, YOU'RE, NEXT, UH HUH, UR, HOLD, WHAT?, YOU, UH UH, LIKE, DONE, U",
            "YOU ARE": "YOUR, NEXT, LIKE, UH HUH, WHAT?, DONE, UH UH, HOLD, YOU, U, YOU'RE, SURE, UR, YOU ARE",
            "YOUR": "UH UH, YOU ARE, UH HUH, YOUR, NEXT, UR, SURE, U, YOU'RE, YOU, WHAT?, HOLD, LIKE, DONE",
            "YOU'RE": "YOU, YOU'RE, UR, NEXT, UH UH, YOU ARE, U, YOUR, WHAT?, UH HUH, SURE, DONE, LIKE, HOLD",
            "UR": "DONE, U, UR, UH HUH, WHAT?, SURE, YOUR, HOLD, YOU'RE, LIKE, NEXT, UH UH, YOU ARE, YOU",
            "U": "UH HUH, SURE, NEXT, WHAT?, YOU'RE, UR, UH UH, DONE, U, YOU, LIKE, HOLD, YOU ARE, YOUR",
            "UH HUH": "UH HUH, YOUR, YOU ARE, YOU, DONE, HOLD, UH UH, NEXT, SURE, LIKE, YOU'RE, UR, U, WHAT?",
            "UH UH": "UR, U, YOU ARE, YOU'RE, NEXT, UH UH, DONE, YOU, UH HUH, LIKE, YOUR, SURE, HOLD, WHAT?",
            "WHAT?": "YOU, HOLD, YOU'RE, YOUR, U, DONE, UH UH, LIKE, YOU ARE, UH HUH, UR, NEXT, WHAT?, SURE",
            "DONE": "SURE, UH HUH, NEXT, WHAT?, YOUR, UR, YOU'RE, HOLD, LIKE, YOU, U, YOU ARE, UH UH, DONE",
            "NEXT": "WHAT?, UH HUH, UH UH, YOUR, HOLD, SURE, NEXT, LIKE, DONE, YOU ARE, UR, YOU'RE, U, YOU",
            "HOLD": "YOU ARE, U, DONE, UH UH, YOU, UR, SURE, WHAT?, YOU'RE, NEXT, HOLD, UH HUH, YOUR, LIKE",
            "SURE": "YOU ARE, DONE, LIKE, YOU'RE, YOU, HOLD, UH HUH, UR, SURE, U, WHAT?, NEXT, YOUR, UH UH",
            "LIKE": "YOU'RE, NEXT, U, UR, HOLD, DONE, UH UH, WHAT?, UH HUH, YOU, LIKE, SURE, YOU ARE, YOUR"
        }
        word_list = [x.strip() for x in priorities.get(label_to_read, "").split(',')]
        for word in word_list:
            if word in buttons: return word
        return buttons[0]

    def solve_memory(self, data):
        stage = data['stage']
        display = int(data['display'])
        pos = 0; lbl = 0
        if stage == 1:
            if display == 1: pos = 2
            elif display == 2: pos = 2
            elif display == 3: pos = 3
            elif display == 4: pos = 4
        elif stage == 2:
            if display == 1: lbl = 4 
            elif display == 2: pos = self.memory_history[0]['pos']
            elif display == 3: pos = 1
            elif display == 4: pos = self.memory_history[0]['pos']
        elif stage == 3:
            if display == 1: lbl = self.memory_history[1]['lbl']
            elif display == 2: lbl = self.memory_history[0]['lbl']
            elif display == 3: pos = 3
            elif display == 4: lbl = 4
        elif stage == 4:
            if display == 1: pos = self.memory_history[0]['pos']
            elif display == 2: pos = 1
            elif display == 3: pos = self.memory_history[1]['pos']
            elif display == 4: pos = self.memory_history[1]['pos']
        elif stage == 5:
            if display == 1: lbl = self.memory_history[0]['lbl']
            elif display == 2: lbl = self.memory_history[1]['lbl']
            elif display == 3: lbl = self.memory_history[3]['lbl']
            elif display == 4: lbl = self.memory_history[2]['lbl']
        self.memory_history.append({'pos': pos, 'lbl': lbl})
        return str(pos) if pos != 0 else str(lbl)

    def solve_morse(self, data):
        freqs = {"shell": "3.505", "halls": "3.515", "slick": "3.522", "trick": "3.532", "boxes": "3.535", "leaks": "3.542", "strobe": "3.545", "bistro": "3.552", "flick": "3.555", "bombs": "3.565", "break": "3.572", "brick": "3.575", "steak": "3.582", "sting": "3.592", "vector": "3.595", "beats": "3.600"}
        return freqs.get(data.get('word', ''), "3.505")

    def solve_complicated(self, data):
        results = []
        for i in range(data['amount']):
            c_str = data['colors'][i].lower()
            red = 'red' in c_str
            blue = 'blue' in c_str
            star, led = data['stars'][i], data['leds'][i]
            mask = (red, blue, star, led)
            logic = {
                (0,0,0,0):'C', (0,0,1,0):'C', (0,0,0,1):'D', (0,0,1,1):'B',
                (0,1,0,0):'S', (0,1,1,0):'D', (0,1,0,1):'P', (0,1,1,1):'P',
                (1,0,0,0):'S', (1,0,1,0):'C', (1,0,0,1):'B', (1,0,1,1):'B',
                (1,1,0,0):'S', (1,1,1,0):'P', (1,1,0,1):'S', (1,1,1,1):'D'
            }
            act = logic.get(mask, 'D')
            if act == 'C': results.append('cut')
            elif act == 'D': results.append('skip')
            elif act == 'S': results.append('cut' if not self.serial_odd else 'skip') 
            elif act == 'P': results.append('cut' if self.parallel else 'skip')
            elif act == 'B': results.append('cut' if self.batteries >= 2 else 'skip')
        return results

    def solve_wire_sequence(self, data):
        results = []
        for wire in data['wires']:
            color = wire['color'].lower()
            target = wire['target'].upper()
            self.wire_seq_counts[color] += 1
            count = self.wire_seq_counts[color]
            valid = ''
            if color == 'red':
                valid = {1:'C', 2:'B', 3:'A', 4:'AC', 5:'B', 6:'AC', 7:'ABC', 8:'AB', 9:'B'}.get(count, '')
            elif color == 'blue':
                valid = {1:'B', 2:'AC', 3:'B', 4:'A', 5:'B', 6:'BC', 7:'C', 8:'AC', 9:'A'}.get(count, '')
            elif color == 'black':
                valid = {1:'ABC', 2:'AC', 3:'B', 4:'AC', 5:'B', 6:'BC', 7:'AB', 8:'C', 9:'C'}.get(count, '')
            results.append('cut' if target in valid else 'skip')
        return results

    def solve_passwords(self, data):
        words = ["about", "after", "again", "below", "could", "every", "first", "found", "great", "house", "large", "learn", "never", "other", "place", "plant", "point", "right", "small", "sound", "spell", "still", "study", "their", "there", "these", "thing", "think", "three", "water", "where", "which", "world", "would", "write"]
        options = data['letters']
        for w in words:
            if all(w[i].upper() in options[i].upper() for i in range(5)): return w
        return words[0]
    
    def solve_mazes(self, data): return "UP" 
    def solve_knobs(self, data): return "UP"

    # ---------------- MAIN LOOP ----------------
    def run(self):
        self.parse_header()
        self.r.sendlineafter(b"(press Enter):", b"90")

        for i in range(1, 101):
            try:
                # In ra số module để biết tiến độ (nhưng ngắn gọn)
                if i % 10 == 0: print(f" [*] Đang giải module {i}/100...")
                
                self.r.recvuntil(b"Module: ")
                module_name = self.r.recvline().strip().decode()
                self.r.recvuntil(b"Data: ")
                raw_data = self.r.recvline().strip().decode()
                data = ast.literal_eval(raw_data)
                
                if module_name == "Wires":
                    ans = self.solve_wires(data)
                    self.r.sendlineafter(b":", str(ans).encode())
                elif module_name == "Complicated Wires":
                    ans_list = self.solve_complicated(data)
                    for idx, act in enumerate(ans_list):
                        self.r.sendlineafter(f"Wire {idx+1}:".encode(), act.encode())
                elif module_name == "Keypads":
                    ans = self.solve_keypads(data)
                    self.r.sendlineafter(b":", ans.encode())
                elif module_name == "Button":
                    action, release_digit = self.solve_button(data)
                    choice = "1" if action == "press" else "2"
                    self.r.sendlineafter(b"(1 or 2):", choice.encode())
                    if action == "hold": self.r.sendlineafter(b"(0-9):", str(release_digit).encode())
                elif module_name == "Simon Says":
                    ans = self.solve_simon(data)
                    self.r.sendlineafter(b":", ans.encode())
                elif module_name == "Who's on First":
                    ans = self.solve_wof(data)
                    self.r.sendlineafter(b":", ans.encode())
                elif module_name == "Memory":
                    ans = self.solve_memory(data)
                    self.r.sendlineafter(b":", ans.encode())
                elif module_name == "Wire Sequences":
                    ans_list = self.solve_wire_sequence(data)
                    self.r.sendlineafter(b":", str(ans_list).encode()) 
                elif module_name == "Passwords":
                    ans = self.solve_passwords(data)
                    self.r.sendlineafter(b":", ans.encode())
                elif module_name == "Morse Code":
                    ans = self.solve_morse(data)
                    self.r.sendlineafter(b":", ans.encode())
                elif module_name == "Knobs":
                    ans = self.solve_knobs(data)
                    self.r.sendlineafter(b":", ans.encode())
                elif module_name == "Mazes":
                    ans = self.solve_mazes(data)
                    self.r.sendlineafter(b":", ans.encode())
                else:
                    self.r.sendline(b"1") 

                # Kiểm tra BOOM hoặc Game Over (chỉ check khi cần thiết)
                # res = self.r.recvline() # Bỏ qua để tiết kiệm thời gian, chỉ bắt exception

                if i < 100:
                    self.r.sendlineafter(b"(press Enter):", str(i+1).encode())
                    
            except Exception as e:
                # Chỉ in lỗi khi thực sự crash
                print(f" [!] Lỗi tại module {i}: {e}")
                # Nếu lỗi là EOFError, nghĩa là đã game over hoặc boom
                break
        
        self.r.interactive()

if __name__ == "__main__":
    conn = remote(HOST, PORT)
    solver = BombSolver(conn)
    solver.run()