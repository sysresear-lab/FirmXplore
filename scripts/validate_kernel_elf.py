"""Reject incomplete ELF firmware-emulation kernels before image creation."""
from pathlib import Path
import struct
import sys


def validate(path):
    data = Path(path).read_bytes()
    if data[:4] != b'\x7fELF' or data[4] != 1 or data[5] not in (1, 2) or len(data) < 52:
        raise ValueError(f'{path}: expected complete ELF32 kernel')
    order = '<' if data[5] == 1 else '>'
    offset = struct.unpack_from(order+'I', data, 28)[0]
    size, count = struct.unpack_from(order+'HH', data, 42)
    if size < 32 or count < 1 or offset + size*count > len(data):
        raise ValueError(f'{path}: invalid program header table')
    for index in range(count):
        header = struct.unpack_from(order+'8I', data, offset + index*size)
        if header[1] + header[4] > len(data):
            raise ValueError(f'{path}: truncated segment {index}: requires {header[1]+header[4]} bytes, found {len(data)}')
    return {'path': str(path), 'bytes': len(data), 'segments': count}


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        print(validate(filename))
