
with open('index.html', 'rb') as f:
    lines = f.readlines()
    for i in range(4245, 4260):
        print(f"{i+1}: {repr(lines[i])}")
