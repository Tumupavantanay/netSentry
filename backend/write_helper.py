import sys
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(sys.stdin.read())
print("OK")
