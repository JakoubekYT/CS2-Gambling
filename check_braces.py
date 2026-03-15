
with open('index.html', 'r', encoding='utf-8') as f:
    content = f.read()

import re
scripts = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)

for i, script in enumerate(scripts):
    stack = []
    lines = script.split('\n')
    for l_idx, line in enumerate(lines):
        for char in line:
            if char == '{':
                stack.append(('{', l_idx + 1))
            elif char == '}':
                if not stack:
                    print(f"Extra '}}' in script {i} at line {l_idx + 1}: {line.strip()}")
                else:
                    stack.pop()
    if stack:
        print(f"Unclosed braces in script {i}:")
        for brace, line_no in stack:
            print(f"  '{brace}' opened at line {line_no}")
