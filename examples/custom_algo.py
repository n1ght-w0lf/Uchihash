def ROR4(val, bits, bit_size=32):
    return ((val & (2 ** bit_size - 1)) >> bits % bit_size) | \
           (val << (bit_size - (bits % bit_size)) & (2 ** bit_size - 1))

def hashme(s):
    res = 0
    for c in s:
        v3 = ROR4(res, 13)
        v4 = c - 32
        if c < 97:
            v4 = c
        res = v4 + v3
    return hex(res)