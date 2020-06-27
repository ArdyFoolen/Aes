# Aes
Aes implementation

- [x] Implement Aes
- [x] Add different padding schemes
- [x] Add encryption mode

##### Padding schemes

- [x] PKCS7
- [x] One and Zeros
- [x] ANSIX923
- [x] ISO10126

##### Encryption mode

- [x] Electronic Code Block (ECB)

	Every block is encrypted and decrypted separately.
	
- [x] Cipher Block Chain (CBC

	Before encryption the plain text block is XORed with the previous cipher text block,
	except the first block which is XORed with an initialization vector (IV).
	
- [x] Counter mode (CTR)

	Here the initialization vector that is past consist only of 12 bytes,
	the last 4 bytes is added with a counter that increments after every block.
	Here the IV is encrypted and after encryption XORed with the plain text.
	This is a streaming encryption and no padding is needed.
	
- [ ] Galois Counter Mode (GCM)

	This is Authenticated Encryption with Associated Data (AEAD)


## Implementation

## Aes Key expansion

### Calculating Round Constants

rcon for round i (rconi) = **| rci 0x00 0x00 0x00 |** rci is the first byte in a 32 bit dword

1. rci for round 1 = 0x01
2. All subsequent rounds the value from the previous round is multiplied by 2.
3. If the value in the previous round >= 0x80, then after multiplication the value is XORed with 0x11B

Round | Value | Explanation | rcon
----- | ----- | ----------- | ----
1 | 0x01 | See above (1) | 0x01000000
2 | 0x02 | 0x01 * 2, See (2) | 0x02000000
3 | 0x04 | 0x02 * 2, See (2) | 0x04000000
4 | 0x08 | 0x04 * 2, See (2) | 0x08000000
5 | 0x10 | 0x08 * 2, See (2) | 0x10000000
6 | 0x20 | 0x10 * 2, See (2) | 0x20000000
7 | 0x40 | 0x20 * 2, See (2) | 0x40000000
8 | 0x80 | 0x40 * 2, See (2) | 0x80000000
9 | 0x1B | (0x80 * 2) = 0x100 ^ 0x11B = 0x1B, See (3) | 0x1B000000
10 | 0x36 | 0x1B * 2, See (2) | 0x36000000
11 | 0x6C | 0x36 * 2, See (2) | 0x6C000000
12 | 0xD8 | 0x6C * 2, See (2) | 0xD8000000
13 | 0xAB | (0xD8 * 2) = 0x1B0 ^ 0x11B = 0xAB, See (3) | 0xAB000000
14 | 0x4D | (0xAB * 2) = 0x156 ^ 0x11B = 0x4D, See (3) | 0x4D000000
15 | 0x9A | (0x4D * 2), See (2)	| 0x9A000000
    
### KeySchedule

	Definitions

	N				As the length of the key in 32 bits dwords, For 128 = 4, 192 = 6, 256 = 8.
	K0, K1, K2, ..., K(N-1)		32 bits dwords of the original key
	R				Number of rounds, 128 = 11, 192 = 13, 256 = 15.
	W0, W1, W2, ..., W(4R-1)	32 bits dwords of the expanded key
	i				0 ... 4R-1
	RotWord([ b0, b1, b2, b3 ]) = [ b1, b2, b3, b0 ]		One byte Left circular shift of dword
	SubWord([ b0, b1, b2, b3 ]) = [ S(b0), S(b1), S(b2), S(b3) ]	Substitute byte according S-Box

	Condition                       	Calculate new key
	i < N			 		Wi = Ki
	i >= N && (i % N) == 0			Wi = Wi-N ^ SubWord(RotWord(Wi-1)) ^ rconi
	i >= N && N > 6 && (i % N) == 4		Wi = Wi-N ^ SubWord(Wi-1)
	otherwise				Wi-N ^ Wi-1

## MixColumns

### State
  
Encryption takes place over 128 bit input blocks (your plain text), regardsless of the size of the key. This state
can be achieved by changing either the input to a 2 dimensional array of 4 bytes by 4 bytes, 4 rows by 4 columns,
or by using the index formula r + 4 * c over the input.

### Calculate MixColumns
  
1. Take a column of bytes from the input. 4 bytes because there are always only 4 rows, see State above.
2. Multiply by matrix:
  
  - | 2 3 1 1 | = Value row 1
  - | 1 2 3 1 | = Value row 2
  - | 1 1 2 3 | = Value row 3
  - | 3 1 1 2 | = Value row 4
     
3. To reverse simply take in the same as in point 1 the 4 bytes of the encrypted text, also see State above.
4. Multiply by matrix:
  
  - | E B D 9 | = Original Value row 1
  - | 9 E B D | = Original Value row 2
  - | D 9 E B | = Original Value row 3
  - | B D 9 E | = Original Value row 4
  
### How to calculate

	Example column of input bytes: db 13 53 45
	Example column of encrypted  : 8e 4d a1 bc
  
	db 13 53 45 *	| 2 3 1 1 | = db * 2 xor 13 * 3 xor 53     xor 45     = 8e
			| 1 2 3 1 | = db     xor 13 * 2 xor 53 * 3 xor 45     = 4d
			| 1 1 2 3 | = db     xor 13     xor 53 * 2 xor 45 * 3 = a1
			| 3 1 1 2 | = db * 3 xor 13     xor 53     xor 45 * 2 = bc

#### Multiplication
  
All above numbers are in hex. For readability I put a space between 4 bits.
  
1. Change to binary db = 1101 1011
2. Shift, move all bits 1 position to the left. Most significant bit gets lost, least significat bit becomes 0.
	1101 1011 << 1 = 1011 0110
3. If before the shift the most significant bit is 1, xor with 1b = 0001 1011 in binary.
	- 1011 0110
	- 0001 1011
	- 1010 1101 = ad in hex
4. The result in point 3 is the multiplication of db by 2 = ad.
5. Now multiply 13 by 3, 3 in binary = 0011 = 0010 xor 0001. Which means first multiply by 2 and then xor with the original value.
	- 0001 0011 << 1 = 0010 0110 (No need for step 3)

	- 0010 0110 (result of x2)
	- 0001 0011 (xor with original value = 13 hex)
	- 0011 0101 = 35 in hex
6. Now xor all the 4 results together. (No need to calculate the 2 x1 multiplication)

	- ad = 1010 1101
	- 35 = 0011 0101
	-    = 1001 1000 xor
	- 53 = 0101 0011
	-    = 1100 1011 xor
	- 45 = 0100 0101
	-    = 1000 1110 = 8e This is your first number see result above.
7. Now calculate the other 3 numbers with the above formulas.

Note: To calculate with E:
1. Change to Binary e = 1110 = 1000 xor 0100 xor 0010
2. Xor the multiplication of 8 * the value with 4 times the value with 2 times the value together.
3. To multiply by 8, you have to multiply 3 times with 2, and do not forget to xor with 1b every time if necessary.
4. After the 8 multiplication you also already have the x4 and x2 values to be used in your final xor.

	- e.g: e * 8e
	- 8e = 1000 1110 << 1 = 0001 1100
	- 		      	0001 1011 (1b because of high bit)
	- 		      	0000 0111 x2
	-      0000 0111 << 1 = 0000 1110 x4 (No high bit)
	-      0000 1110 << 1 = 0001 1100 x8 (No high bit)

	-    0000 0111 x2
	-    0000 1110 x4
	-  = 0000 1001 xor
	-    0001 1100 x8
	-  = 0001 0101 = 15 in hex result

5. b = 1011 = 1000 xor 0010 xor 0001, See multiplication of e, except in final xor take x8, x2 and x1
6. d = 1101 = 1000 xor 0100 xor 0001, See multiplication of e, except in final xor take x8, x4 and x1
7. 9 = 1001 = 1000 xor 0001, See multiplication of e, except in final xor take x8 and x1
