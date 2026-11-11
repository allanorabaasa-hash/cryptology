from collections import Counter
import string
message = '''
PATIENT HEALTH RECORDS CONTAIN SENSITIVE INFORMATION THAT 
MUST BE PROTECTED FROM UNAUTHORIZED ACCESS. HOSPITAL STAFF 
SHOULD FOLLOW SECURITY POLICIES WHEN HANDLING DATA AND USE 
STRONG PASSWORDS TO PREVENT DATA BREACHES. REGULAR TRAINING 
HELPS EMPLOYEES UNDERSTAND THEIR RESPONSIBILITIES AND REDUCES 
THE RISK OF ACCIDENTAL DISCLOSURE OF CONFIDENTIAL INFORMATION.
'''
ciphertext = '''
SDWLHQW KHDOWK UHFRUGV FRQWDLQ VHQVLWLYH 
LQIRUPDWLRQ WKDW PXVW EH SURWHFWHG IURP XQDXWKRULCHG 
DFFHVV. KRVSLWDO VWDII VKRXOG IROORZ VHFXULWB SROLFLHV 
ZKHQ KDQGOLQJ GDWD DQG XVH VWURQJ SDVVZRUGV WR SUHYHQW 
GDWD EUHDFKHV. UHJXODU WUDLQLQJ KHOSV HPSORBHHV XQGHUVWDQG 
WKHLU UHVSRQVLELOLWLHV DQG UHGXFHV WKH ULVN RI DFFLGHQWDO 
GLVFORVXUH RI FRQILGHQWLDO LQIRUPDWLRQ.
'''
letters = [c for c in ciphertext if c.isalpha()]
freq = Counter(letters)

print("Letter Frequencies:")
for letter, count in freq.most_common():
    print(f"{letter}: {count}")

# Assume the most frequent ciphertext letter corresponds to E
most_common = freq.most_common(1)[0][0]
shift = (ord(most_common) - ord('E')) % 26

print("\nEstimated Shift:", shift)

# Decrypt using estimated shift
plaintext = ""

for char in ciphertext:
    if char.isalpha():
        decrypted = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
        plaintext += decrypted
    else:
        plaintext += char

print("\nRecovered Plaintext:")
print(plaintext)