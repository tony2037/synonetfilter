from random import randint

Scales = {
        'KB': 1,
        'MB': 2,
        'GB': 3,
        }
FF = 0xff.to_bytes(1, byteorder='big')
ZERO = 0x00.to_bytes(1, byteorder='big')

Result = []

def write(File, size, zero_pos):

    for i in range(zero_pos):
        File.write(FF)
    File.write(ZERO)
    for i in range(size - zero_pos - 1):
        File.write(FF)

for key, val in Scales.items():
    size = 1024 ** val
    zero_pos = randint(0, size)
    file_name = f'1{key}_{zero_pos}'
    Result.append(file_name)
    with open(file_name, 'wb') as f:
        write(f, size, zero_pos)
        f.close()

print('Generate:')
for file_name in Result:
    print(file_name)
