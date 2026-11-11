"""
Task 5 — Hamming (7,4) and cyclic (7,4) code with g(x)=x^3+x+1.
Bit convention: data bits d1 d2 d3 d4; parity positions 1,2,4; codeword positions 1..7.
"""
def hamming74_encode(data):
    if len(data) != 4 or set(data) - {"0","1"}:
        raise ValueError("Expected four bits")
    d1,d2,d3,d4 = map(int,data)
    # even parity: p1 covers positions 1,3,5,7; p2 covers 2,3,6,7; p4 covers 4,5,6,7
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p4 = d2 ^ d3 ^ d4
    # positions [p1,p2,d1,p4,d2,d3,d4]
    return "".join(map(str,[p1,p2,d1,p4,d2,d3,d4]))

def hamming74_decode(code: str):
    if len(code)!=7 or set(code)-{"0","1"}: raise ValueError("Expected seven bits")
    b = [None] + list(map(int,code))
    s1 = b[1]^b[3]^b[5]^b[7]
    s2 = b[2]^b[3]^b[6]^b[7]
    s4 = b[4]^b[5]^b[6]^b[7]
    syndrome = s4*4 + s2*2 + s1
    corrected = b[:]
    if syndrome:
        corrected[syndrome] ^= 1
    corrected_word = "".join(map(str,corrected[1:]))
    data = "".join(str(corrected[i]) for i in (3,5,6,7))
    return syndrome, corrected_word, data




def main():
    print("TASK 5 — ERROR DETECTION AND CORRECTION")
    word = hamming74_encode("1011")
    print("Hamming(7,4) encode 1011:", word)
    # Flip position 6 (1-based from left).
    corrupted = list(word)
    corrupted[5] = "1" if corrupted[5]=="0" else "0"
    corrupted = "".join(corrupted)
    syndrome, corrected, data = hamming74_decode(corrupted)
    print("Corrupt position 6:", corrupted)
    print("Syndrome C4 C2 C1:", format((syndrome>>2)&1,"b"), format((syndrome>>1)&1,"b"), format(syndrome&1,"b"), "(binary position =", syndrome, ")")
    print("Corrected codeword:", corrected, "recovered data:", data)


if __name__ == "__main__":
    main()
