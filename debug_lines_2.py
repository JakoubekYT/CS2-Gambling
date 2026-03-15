
with open('index.html', 'rb') as f:
    file_lines = f.readlines()
    for i, line in enumerate(file_lines):
        if b"async function renderCaseBattleRoom" in line:
            print(f"MATCH: line {i+1}: {repr(line)}")
            for j in range(i, i + 300):
                if j < len(file_lines):
                    target_line = file_lines[j]
                    if b"animateCaseBattleRounds" in target_line:
                        print(f"FOUND animate at line {j+1}: {repr(target_line)}")
