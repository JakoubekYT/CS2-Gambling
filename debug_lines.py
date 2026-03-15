
with open('index.html', 'rb') as f:
    lines = f.readlines()
    for i in range(3419, 3425):
        print(f"{i+1}: {repr(lines[i])}")
    for i in range(3548, 3555):
        print(f"{i+1}: {repr(lines[i])}")
