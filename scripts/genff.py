import sys

if (len(sys.argv) < 3):
    exit()
p = 0xff.to_bytes(1, byteorder='big')
size = int(sys.argv[1])
file_name = sys.argv[2]
print(f'stuff {size} 0xff into {file_name}')

with open(file_name, 'wb') as f:
    for _ in range(size):
        f.write(p)
    f.close()
