"""
BITCOIN ADDRESS GENERATION — MATHEMATICAL EDITION
=================================================

Purpose
-------
This program derives Bitcoin public keys, Wallet Import Format (WIF) private
keys, and legacy Pay-to-Public-Key-Hash (P2PKH) addresses from a private key.

Notation and arithmetic conventions
------------------------------------
1. All numerical constants in this edition are written in DECIMAL notation.
   For example, the secp256k1 field prime is written as a decimal integer,
   not as a hexadecimal integer.

2. The symbol "%" means the mathematical remainder operation. In expressions
   modulo p, values are reduced to their representative in {0, 1, ..., p-1}.

3. A 32-bit word is an integer restricted to the range 0 through 2^32 - 1.
   The decimal number 4294967295 is therefore the 32-bit mask.

4. A byte is an integer from 0 through 255. A sequence of bytes is the
   representation used by the hashing and Bitcoin serialization procedures.

5. "Big-endian" means that the most significant byte is stored first.
   "Little-endian" means that the least significant byte is stored first.

6. Python's bitwise operators &, |, ^, ~, <<, and >> operate on integer
   bit patterns. They are used by SHA-256 and RIPEMD-160 to mix information.

IMPORTANT MATHEMATICAL DISTINCTION
----------------------------------
Elliptic-curve arithmetic is performed modulo the field prime p.
SHA-256 and RIPEMD-160 operate on fixed-width 32-bit words and byte blocks.
Base58 is an integer-to-text encoding; it is not a cryptographic hash.

The program's high-level chain is:

    private integer d
        -> elliptic-curve point Q = dG
        -> serialized public key
        -> SHA-256(public key)
        -> RIPEMD-160(SHA-256(public key))
        -> versioned payload and checksum
        -> Base58Check address

The WIF string is generated separately from the private integer d.

SECURITY WARNING
----------------
A real private key controls funds. Never paste a real private key into an
untrusted computer, website, or shared environment. This implementation is
for mathematical study and should be independently tested before use with
valuable funds.
"""

#########################################BTC_CONSTANTS####################################################################
# Bitcoin curve constants in hexadecimal
# Field modulus p. Every secp256k1 coordinate calculation is reduced modulo p.
prime = 115792089237316195423570985008687907853269984665640564039457584007908834671663  # Prime number for the Bitcoin elliptic curve
# Curve coefficient a in y^2 = x^3 + a*x + b; secp256k1 has a = 0.
curve_a = 0  # 'a' parameter of the elliptic curve equation (y^2 = x^3 + ax + b)
# Curve coefficient b; therefore the curve is y^2 = x^3 + 7 (mod p).
curve_b = 7  # 'b' parameter of the elliptic curve equation
# The fixed generator point G=(generator_x, generator_y) on secp256k1.
generator_x = 55066263022277343669578718895168534326250603453777594175500187360389116729240  # x-coordinate of the generator point
generator_y = 32670510020758816978083085130507043184471273380659243275938904335757337482424  # y-coordinate of the generator point

#########################################Eliptic_Curve_Math_for_Public_key################################################

def point_addition(point1, point2, prime):
    """
    Elliptic-curve group addition on secp256k1.

    The curve is y^2 = x^3 + 7 (mod p), where p is the field prime.

    Given P=(x1,y1) and R=(x2,y2), this computes P+R. The result is another
    point on the same curve. The special pair (0,0) is used here as the
    program's representation of the point at infinity, the identity element.

    If P and R are distinct, the slope is
        m = (y2-y1) / (x2-x1)  (mod p).

    If P=R, the tangent slope is
        m = (3*x1^2 + a) / (2*y1)  (mod p).

    Division modulo p is multiplication by a modular inverse. Since p is
    prime, Fermat's little theorem gives z^(-1) = z^(p-2) (mod p), for
    nonzero z. Python's pow(z, p-2, p) calculates that modular power.

    The resulting coordinates are
        x3 = m^2 - x1 - x2  (mod p)
        y3 = m*(x1-x3) - y1 (mod p).

    In plain English: the function finds the third curve point determined
    by the line through two points, or by the tangent when they are equal.
    """  # Function to add two points on the elliptic curve
    if point1 == (0, 0):  # If point1 is the point at infinity
        return point2  # Return point2
    if point2 == (0, 0):  # If point2 is the point at infinity
        return point1  # Return point1
    if point1 == point2:  # If the points are the same (point doubling)
        slope = (3 * point1[0]**2 + curve_a) * pow(2 * point1[1], prime - 2, prime) % prime  # Calculate slope for point doubling
    else:  # If the points are different
        slope = (point2[1] - point1[1]) * pow(point2[0] - point1[0], prime - 2, prime) % prime  # Calculate slope for point addition
    result_x = (slope * slope - point1[0] - point2[0]) % prime  # Calculate x-coordinate of the result
    result_y = (slope * (point1[0] - result_x) - point1[1]) % prime  # Calculate y-coordinate of the result
    return (result_x, result_y)  # Return the resulting point

def scalar_multiplication(private_key, generator_point, prime):
    """
    Compute Q = dG, where d is the private integer and G is the fixed
    secp256k1 generator point.

    This is repeated elliptic-curve addition, implemented efficiently by
    the binary (double-and-add) method.

    Write d in base 2:
        d = b0*2^0 + b1*2^1 + ... + bk*2^k,
    where every bit bi is either 0 or 1.

    The algorithm successively forms G, 2G, 4G, 8G, ... by point doubling.
    Whenever the current bit of d is 1, that multiple is added to the result.

    In plain English: the private key determines how many times the
    generator point is added to itself, without performing d additions
    individually. The final point is the public key point.
    """  # Function for scalar multiplication
    result = (0, 0)  # Initialize result as point at infinity
    current_point = generator_point  # Set current point to the generator point
    while private_key > 0:  # Loop while private key is greater than 0
        if private_key % 2 == 1:  # If least significant bit of private key is 1
            result = point_addition(result, current_point, prime)  # Add current point to result
        current_point = point_addition(current_point, current_point, prime)  # Double the current point
        private_key //= 2  # Divide private key by 2 (right shift by 1 bit)
    return result  # Return the final result of scalar multiplication

#########Final_point_X,Y_ is taken and padded with 02 or 04 outputs compressed and uncompressed public key###############

def to_uncompressed_hex(point):
    """
    Serialize a curve point as an uncompressed SEC public key.

    The format is:
        04 || X || Y

    Here X and Y are each exactly 32 bytes (256 bits), most-significant
    byte first. The leading byte 04 identifies the uncompressed format.

    This changes the representation of the point, not the point itself.
    """  # Function to convert a point to uncompressed hex format
    x, y = point  # Unpack the x and y coordinates from the point tuple
    return '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()  # Return the uncompressed hex representation

def to_compressed_hex(point):
    """
    Serialize a curve point as a compressed SEC public key.

    The format is:
        02 || X, when Y is even
        03 || X, when Y is odd

    The curve equation determines Y^2 from X. For a valid X there are
    generally two possible roots, Y and p-Y; their parities differ.
    The prefix records which root is intended, so only X needs to be stored.

    This reduces the public-key representation from 65 bytes to 33 bytes.
    """  # Function to convert a point to compressed hex format
    x, y = point  # Unpack the x and y coordinates from the point tuple
    return ('02' if y % 2 == 0 else '03') + x.to_bytes(32, 'big').hex()  # Return the compressed hex representation

####################################################PRIVATE_KEY_TO_WIF########################################################
# Base58 encoding
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'  # The characters used in Base58 encoding

def base58_encode(data):
    """
    Convert a byte sequence into the Bitcoin Base58 alphabet.

    Interpret the bytes as one nonnegative big-endian integer N. Repeatedly
    divide N by 58. Each remainder is the next Base58 digit, and the
    quotient is used for the next division. The remainders are collected
    from least significant to most significant, so they are reversed.

    Leading zero bytes need special treatment: each is represented by the
    Base58 character '1'. This preserves the original byte sequence exactly.

    Base58 is an encoding, not encryption and not a hash.
    """
    # Convert the input byte data to an integer
    n = int.from_bytes(data, 'big')  # Interpret the byte sequence as a big-endian integer
    
    # Encode to Base58
    res = []  # Initialize the result list to collect Base58 characters
    while n > 0:
        n, r = divmod(n, 58)  # Divide n by 58, r is the remainder
        res.append(BASE58_ALPHABET[r])  # Append the corresponding Base58 character
    res = ''.join(res[::-1])  # Reverse the result list to get the correct order
    
    # Add '1' characters for leading zero bytes (each 0 byte corresponds to a '1')
    pad = ''
    for byte in data:
        if byte == 0:  # For each leading zero byte
            pad += '1'  # Prepend a '1' to the padding
        else:
            break  # Stop padding after the first non-zero byte
    
    return pad + res  # Return the padded Base58 encoded string

def to_wif(private_key, compressed=False, testnet=False):
    """
    Encode a private integer in Wallet Import Format (WIF).

    Mainnet uses version byte 128; testnet uses version byte 239.
    The private integer is represented by exactly 32 big-endian bytes.
    Compressed-key WIF appends the marker byte 1.

    The checksum is the first four bytes of SHA256(SHA256(payload)).
    The payload and checksum are concatenated and Base58-encoded.

    The compressed marker does not change the private integer. It tells
    wallet software to derive/use the compressed public-key serialization.
    """
    # Convert the private key (integer) to bytes, 32 bytes long
    private_key_bytes = private_key.to_bytes(32, 'big')
    
    # Add version byte: 239 for testnet, 128 for mainnet
    version = bytes([239]) if testnet else bytes([128])  # Determine the version byte based on the network
    extended_key = version + private_key_bytes  # Concatenate version byte and private key bytes
    
    # Add compression flag if needed
    if compressed:
        extended_key += bytes([1])  # Append the compression flag to the extended key
    
    # Compute the checksum (first 4 bytes of double SHA256)
    checksum = double_sha256(extended_key)[:4]  # Calculate the checksum for integrity
    
    # Concatenate the extended key and checksum
    binary = extended_key + checksum  # Create the binary data to be encoded
    
    # Encode the binary data in Base58
    wif = base58_encode(binary)  # Convert binary data to Base58 format
    
    return wif  # Return the Wallet Import Format string

#######################################SHA256_FUNCTION####################################################################


def rotr(x, n):
    """
    Rotate a 32-bit word x right by n bit positions.

    Bits shifted out of the right end re-enter at the left end. Unlike a
    normal right shift, rotation does not discard bits. The mask keeps the
    result within 32 bits.
    """  # Function to perform right rotation on a 32-bit number
    return (x >> n) | (x << (32 - n)) & 4294967295  # Perform right rotation and return the result

K = [  # These are the first 64 bits of the fractional parts of the cube roots of the first 64 prime numbers
    1116352408,  # 1116357408  ∛2 ≈ 1.259921  0.259921×2^32 ≈ 1116357408
    1899447441,  # 1682555249  ∛3 ≈ 1.442250  0.442250×2^32 ≈ 1682555249
    3049323471,  # 3044654991  ∛5 ≈ 1.710000  0.710000×2^32 ≈ 3044654991
    3921009573,  # 3891354453  ∛7 ≈ 1.912931  0.912931×2^32 ≈ 3891354453
    961987163,  # 960205659   ∛11 ≈ 2.223980  0.223980×2^32 ≈ 960205659
    1508970993,  # 1504372593  ∛13 ≈ 2.351083  0.351083×2^32 ≈ 1504372593
    2453635748,  # 2452134132  ∛17 ≈ 2.571281  0.571281×2^32 ≈ 2452134132
    2870763221,  # 2882350805  ∛19 ≈ 2.668401  0.668401×2^32 ≈ 2882350805
    3624381080,  # 3604570700  ∛23 ≈ 2.843867  0.843867×2^32 ≈ 3604570700
    310598401,  # 493352449   ∛29 ≈ 3.072316  0.072316×2^32 ≈ 493352449
    607225278,  # 604823847   ∛31 ≈ 3.141376  0.141376×2^32 ≈ 604823847
    1426881987,  # 1430350963  ∛37 ≈ 3.332290  0.332290×2^32 ≈ 1430350963
    1925078388,  # 1921589732  ∛41 ≈ 3.448163  0.448163×2^32 ≈ 1921589732
    2162078206,  # 2169555822  ∛43 ≈ 3.523509  0.523509×2^32 ≈ 2169555822
    2614888103,  # 2622760935  ∛47 ≈ 3.634241  0.634241×2^32 ≈ 2622760935
    3248222580,  # 3245565700  ∛53 ≈ 3.786251  0.786251×2^32 ≈ 3245565700
    3835390401,  # 3897578497  ∛59 ≈ 3.892257  0.892257×2^32 ≈ 3897578497
    4022224774,  # 4023233410  ∛61 ≈ 3.952847  0.952847×2^32 ≈ 4023233410
    264347078,  # 1776935702  ∛67 ≈ 4.041453  0.041453×2^32 ≈ 1776935702
    604807628,  # 605467447   ∛71 ≈ 4.120001  0.120001×2^32 ≈ 605467447
    770255983,  # 771700815   ∛73 ≈ 4.161913  0.161913×2^32 ≈ 771700815
    1249150122,  # 1242067130  ∛79 ≈ 4.309728  0.309728×2^32 ≈ 1242067130
    1555081692,  # 1541459220  ∛83 ≈ 4.392268  0.392268×2^32 ≈ 1541459220
    1996064986,  # 1990655154  ∛89 ≈ 4.438514  0.438514×2^32 ≈ 1990655154
    2554220882,  # 2544952498  ∛97 ≈ 4.642219  0.642219×2^32 ≈ 2544952498
    2821834349,  # 2824027757  ∛101 ≈ 4.749374  0.749374×2^32 ≈ 2824027757
    2952996808,  # 2949503608  ∛103 ≈ 4.831611  0.831611×2^32 ≈ 2949503608
    3210313671,  # 3201031740  ∛107 ≈ 4.919919  0.919919×2^32 ≈ 3201031740
    3336571891,  # 3328127631  ∛109 ≈ 5.014063  0.014063×2^32 ≈ 3328127631
    3584528711,  # 3570598471  ∛113 ≈ 5.027794  0.027794×2^32 ≈ 3570598471
    113926993,  # 1479339785  ∛127 ≈ 5.048810  0.048810×2^32 ≈ 1479339785
    338241895,  # 3335086455  ∛131 ≈ 5.078496  0.078496×2^32 ≈ 3335086455
    666307205,  # 670039797   ∛137 ≈ 5.141897  0.141897×2^32 ≈ 670039797
    773529912,  # 778600056   ∛139 ≈ 5.165072  0.165072×2^32 ≈ 778600056
    1294757372,  # 1296270168  ∛149 ≈ 5.246185  0.246185×2^32 ≈ 1296270168
    1396182291,  # 1396289427  ∛151 ≈ 5.252926  0.252926×2^32 ≈ 1396289427
    1695183700,  # 1694219772  ∛157 ≈ 5.285108  0.285108×2^32 ≈ 1694219772
    1986661051,  # 1992671851  ∛163 ≈ 5.394738  0.394738×2^32 ≈ 1992671851
    2177026350,  # 2181296814  ∛167 ≈ 5.398457  0.398457×2^32 ≈ 2181296814
    2456956037,  # 2454201727  ∛173 ≈ 5.542143  0.542143×2^32 ≈ 2454201727
    2730485921,  # 2737021169  ∛179 ≈ 5.643891  0.643891×2^32 ≈ 2737021169
    2820302411,  # 2826730775  ∛181 ≈ 5.667290  0.667290×2^32 ≈ 2826730775
    3259730800,  # 3276744936  ∛191 ≈ 5.854893  0.854893×2^32 ≈ 3276744936
    3345764771,  # 3342525703  ∛193 ≈ 5.898453  0.898453×2^32 ≈ 3342525703
    3516065817,  # 3501189497  ∛197 ≈ 5.906049  0.906049×2^32 ≈ 3501189497
    3600352804,  # 3582653132  ∛199 ≈ 5.929498  0.929498×2^32 ≈ 3582653132
    4094571909,  # 4096392925  ∛211 ≈ 5.973322  0.973322×2^32 ≈ 4096392925
    275423344,  # 2763278176  ∛223 ≈ 5.979237  0.979237×2^32 ≈ 2763278176
    430227734,  # 4317522286  ∛227 ≈ 5.982576  0.982576×2^32 ≈ 4317522286
    506948616,  # 505453696   ∛229 ≈ 5.986922  0.986922×2^32 ≈ 505453696
    659060556,  # 614730380   ∛233 ≈ 5.989236  0.989236×2^32 ≈ 614730380
    883997877,  # 918120517   ∛239 ≈ 5.994713  0.994713×2^32 ≈ 918120517
    958139571,  # 961987075   ∛241 ≈ 5.997393  0.997393×2^32 ≈ 961987075
    1322822218,  # 1350789898  ∛251 ≈ 6.308067  0.308067×2^32 ≈ 1350789898
    1537002063,  # 1541459224  ∛257 ≈ 6.349522  0.349522×2^32 ≈ 1541459224
    1747873779,  # 1742120531  ∛263 ≈ 6.556209  0.556209×2^32 ≈ 1742120531
    1955562222,  # 1962073262  ∛269 ≈ 6.550208  0.550208×2^32 ≈ 1962073262
    2024104815,  # 2029026751  ∛271 ≈ 6.663763  0.663763×2^32 ≈ 2029026751
    2227730452,  # 2227505652  ∛277 ≈ 6.762104  0.762104×2^32 ≈ 2227505652
    2361852424,  # 2362296440  ∛281 ≈ 6.705093  0.705093×2^32 ≈ 2362296440
    2428436474,  # 2436015066  ∛283 ≈ 6.741000  0.741000×2^32 ≈ 2436015066
    2756734187,  # 2763278176  ∛293 ≈ 6.799000  0.799000×2^32 ≈ 2763278176
    3204031479,  # 3202186849  ∛307 ≈ 6.801999  0.801999×2^32 ≈ 3202186849
    3329325298   # 3294908050  ∛311 ≈ 6.842000  0.842000×2^32 ≈ 3294908050
]


def sha256(data):
    """
    Calculate SHA-256 directly from the input bytes.

    SHA-256 maps an arbitrary-length message to a 256-bit digest. It first
    pads the message, divides it into 512-bit blocks, expands each block
    into 64 32-bit words, and performs 64 mixing rounds per block.

    The eight state words are updated after each block. The final digest
    is the concatenation of those eight 32-bit words.

    The rotations, XOR, choice, and majority operations create nonlinear
    and diffusion effects: a small input change produces a substantially
    different digest. Addition is performed modulo 2^32.
    """
    if isinstance(data, str):  # Check if the input data is of type 'str'
        data = data.encode()  # Convert the string to bytes using UTF-8 encoding
    elif isinstance(data, int):  # Check if the input data is of type 'int'
        data = data.to_bytes((data.bit_length() + 7) // 8, 'big')  # Convert the integer to bytes in big-endian format
    
    # These are the first 64 bits of the fractional parts of the square roots of the first 8 prime numbers
    h0 = 1779033703  # 1779033703  √2≈1.414213562  0.414213562×2^32 ≈1779033703
    h1 = 3144134277  # 3144134277  √3≈1.732050808  0.732050808×2^32 ≈3144134277
    h2 = 1013904242  # 1013904242  √5≈2.236067977  0.236067977×2^32 ≈1013904242
    h3 = 2773480762  # 2773480762  √7≈2.645751311  0.645751311×2^32 ≈2773480762
    h4 = 1359893119  # 1359893119  √11≈3.31662479  0.31662479×2^32 ≈1359893119
    h5 = 2600822924  # 2600822924  √13≈3.605551275  0.605551275×2^32 ≈2600822924
    h6 = 528734635  # 528734635   √17≈4.123105625  0.123105625×2^32 ≈528734635
    h7 = 1541459225  # 1541459225  √19≈4.358898944  0.358898944×2^32 ≈1541459225
    
    # Pre-processing: Padding the data according to the SHA-256 specification
    # SHA-256 padding records the original message length in bits.
    length = len(data) * 8            # Original length of the data in bits
    data += bytes([128])                   # Append the bit '1' to the end of the data
    
    # Pad with '0's until the length is congruent to 448 modulo 512
    while (len(data) * 8 + 64) % 512 != 0:
        data += bytes([0])
        
    # Append the original length of the data as a 64-bit big-endian integer
    data += length.to_bytes(8, 'big')


    # Process the message in 512-bit chunks
    for chunk_start in range(0, len(data), 64):  # Iterate over each 512-bit chunk (64 bytes)
        chunk = data[chunk_start:chunk_start + 64]  # Extract the current chunk
        w = [int.from_bytes(chunk[i:i + 4], 'big') for i in range(0, 64, 4)]  # Initialize the first 16 words (32 bits each)

        # Extend the 16 32-bit words into 64 32-bit words
        for i in range(16, 64):
            # Calculate the values using the specified bitwise operations and right rotations
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)  # S0 calculation
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)  # S1 calculation
            # Append the new word to the list after adding the appropriate words and wrapping with & 4294967295
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 4294967295)

        # Initialize working variables to current hash values
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        # Each round mixes the working state with one expanded message word.
        # Main loop for 64 rounds
        # Main loop for 64 rounds
        for i in range(64):
        # Calculate S1 using right rotations of e
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)  # S1: Mix bits of e
            # Select bits based on e's value: choose from f if e is 1, else from g
            ch = (e & f) ^ ((~e) & g)  # ch: Conditional selection function
            # Compute temp1 by combining h, S1, ch, round constant K[i], and word w[i]
            temp1 = (h + S1 + ch + K[i] + w[i]) & 4294967295  # temp1: Intermediate hash value
            # Calculate S0 using right rotations of a
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)  # S0: Mix bits of a
            # Compute maj using majority function
            maj = (a & b) ^ (a & c) ^ (b & c)  # maj: Majority function output
            # Combine S0 and maj to get temp2
            temp2 = (S0 + maj) & 4294967295  # temp2: Another intermediate value
            
            # Update the working variables
            h = g  # h becomes g
            g = f  # g becomes f
            f = e  # f becomes e
            e = (d + temp1) & 4294967295  # e is updated to (d + temp1)
            d = c  # d becomes c
            c = b  # c becomes b
            b = a  # b becomes a
            a = (temp1 + temp2) & 4294967295  # a is updated to (temp1 + temp2)

        # Add the compressed chunk to the current hash value
        h0 = (h0 + a) & 4294967295  # Update h0
        h1 = (h1 + b) & 4294967295  # Update h1
        h2 = (h2 + c) & 4294967295  # Update h2
        h3 = (h3 + d) & 4294967295  # Update h3
        h4 = (h4 + e) & 4294967295  # Update h4
        h5 = (h5 + f) & 4294967295  # Update h5
        h6 = (h6 + g) & 4294967295  # Update h6
        h7 = (h7 + h) & 4294967295  # Update h7

    # Produce the final hash value by concatenating the hash values
    return (h0.to_bytes(4, 'big') + h1.to_bytes(4, 'big') +
            h2.to_bytes(4, 'big') + h3.to_bytes(4, 'big') +
           h4.to_bytes(4, 'big') + h5.to_bytes(4, 'big') +
           h6.to_bytes(4, 'big') + h7.to_bytes(4, 'big'))

def double_sha256(data):
    """
    Apply SHA-256 twice: SHA256(SHA256(data)).

    Bitcoin uses this construction for checksums in formats such as WIF
    and Base58Check addresses. The output remains 256 bits; callers here
    take its first four bytes as the checksum.
    """
    return sha256(sha256(data))  # Perform SHA-256 twice for added security



#######################################RIPEMD160_FUNCTION####################################################################


# RIPEMD-160 constants
# Constants used in the RIPEMD-160 hashing algorithm, divided into two sets based on their function in the algorithm.
RIPEMD160_CONSTANTS_ZERO_SQRT2 = [0, 1518500249, 1859775393, 2400959708, 2840853838]
RIPEMD160_CONSTANTS_SQRT3_ZERO = [1352829926, 1548603684, 1836072691, 2053994217, 0]

# Initial hash values (H0 to H4) for the RIPEMD-160 algorithm
RIPEMD160_h0, RIPEMD160_h1, RIPEMD160_h2, RIPEMD160_h3, RIPEMD160_h4 = (
    1732584193, 4023233417, 2562383102, 271733878, 3285377520
)

# RIPEMD-160 permutation and shift values for each round
RIPEMD160_r = [  # Indices for the first half of the rounds
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
]

RIPEMD160_r_prime = [  # Indices for the second half of the rounds
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
]

# Shift values used in the rounds for mixing
RIPEMD160_s = [  # Shift values for the first half of the rounds
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]

RIPEMD160_s_prime = [  # Shift values for the second half of the rounds
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]

# Helper functions for the RIPEMD-160 algorithm
def RIPEMD160_rotate_left(x, n):
    """
    Rotate a 32-bit word left by n positions, wrapping shifted-out bits
    around to the low-order end. The mask enforces arithmetic modulo 2^32.
    """
    """ Rotate left operation on a 32-bit integer """
    return ((x << n) | (x >> (32 - n))) & 4294967295  # Ensure the result fits in 32 bits

def RIPEMD160_xor(x, y, z):
    """ XOR operation among three values """
    return x ^ y ^ z  # Combine values with XOR

def RIPEMD160_conditional(x, y, z):
    """ Conditional function for mixing bits """
    return (x & y) | (~x & z)  # Standard conditional operation

def RIPEMD160_majority_with_twist(x, y, z):
    """ Majority function with a twist for mixing bits """
    return (x | ~y) ^ z  # Modify the standard majority function

def RIPEMD160_conditional_inverse(x, y, z):
    """ Conditional inverse operation """
    return (x & z) | (y & ~z)  # Invert the conditional logic

def RIPEMD160_xor_or_complement(x, y, z):
    """ XOR and OR with complement """
    return x ^ (y | ~z)  # Combine XOR and OR operations

def RIPEMD160_round(a, b, c, d, e, x, s, k, func):
    """
    Perform one RIPEMD-160 step.

    The selected Boolean function combines three 32-bit state words.
    The message word x and round constant k are added modulo 2^32.
    The sum is rotated left by s positions and then added to e.
    The c register is also rotated left by 10 positions.

    This is one step in a sequence of 80 steps on each of two parallel
    computation lines.
    """
    """ Perform a single round of the RIPEMD-160 hashing process """
    # Update 'a' using the selected function, adding the current block, and the constant
    a = (a + func(b, c, d) + x + k) & 4294967295  # Apply the function and add values
    a = RIPEMD160_rotate_left(a, s) + e  # Rotate left and add 'e'
    c = RIPEMD160_rotate_left(c, 10)  # Rotate 'c' to mix it
    return a & 4294967295, c & 4294967295  # Return the updated values constrained to 32 bits

def RIPEMD160_compress(RIPEMD160_STATE, X):
    """
    Compress one 512-bit message block into the five-word RIPEMD-160 state.

    The 512-bit block is represented as sixteen 32-bit words X[0]...X[15].
    Two parallel lines each execute 80 steps. They use different message
    word orders, rotation counts, Boolean functions, and constants.

    At the end, the two lines are recombined with the previous five-word
    state. This compression step is repeated for every padded message block.
    """
    """ Compress function that implements the core of the RIPEMD-160 algorithm """
    aa, bb, cc, dd, ee = RIPEMD160_STATE  # Unpack the current state
    aaa, bbb, ccc, ddd, eee = RIPEMD160_STATE  # Duplicate for the second half of the round


    # Left line
    for j in range(80):  # Loop over 80 rounds of the RIPEMD-160 hash function.
        if j < 16:  # For the first 16 rounds.
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[0], RIPEMD160_xor)  # Perform a round with specified parameters and XOR operation.
        elif j < 32:  # For rounds 16 to 31.
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[1], RIPEMD160_conditional)  # Use a conditional function for this round.
        elif j < 48:  # For rounds 32 to 47.
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[2], RIPEMD160_majority_with_twist)  # Use majority function with twist for this round.
        elif j < 64:  # For rounds 48 to 63.
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[3], RIPEMD160_conditional_inverse)  # Use a conditional inverse function for this round.
        else:  # For rounds 64 to 79.
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[4], RIPEMD160_xor_or_complement)  # Use an XOR or complement function for this round.
        aa, bb, cc, dd, ee = ee, aa, bb, cc, dd  # Rotate the variables to prepare for the next round.

    # Right line
    for j in range(80):  # Loop over 80 rounds for the second half of the hash function.
        if j < 16:  # For the first 16 rounds.
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[0], RIPEMD160_xor_or_complement)  # Perform a round with specified parameters using an XOR or complement.
        elif j < 32:  # For rounds 16 to 31.
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[1], RIPEMD160_conditional_inverse)  # Use a conditional inverse for this round.
        elif j < 48:  # For rounds 32 to 47.
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[2], RIPEMD160_majority_with_twist)  # Use a majority function with twist for this round.
        elif j < 64:  # For rounds 48 to 63.
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[3], RIPEMD160_conditional)  # Use a conditional function for this round.
        else:  # For rounds 64 to 79.
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[4], RIPEMD160_xor)  # Use an XOR function for this round.
        aaa, bbb, ccc, ddd, eee = eee, aaa, bbb, ccc, ddd  # Rotate the variables to prepare for the next round.
    
    # Combine results
    ddd = (RIPEMD160_STATE[1] + cc + ddd) & 4294967295  # Update the first state variable with the result of the left side and the current value of cc.
    RIPEMD160_STATE[1] = (RIPEMD160_STATE[2] + dd + eee) & 4294967295  # Update the second state variable using the second half's results.
    RIPEMD160_STATE[2] = (RIPEMD160_STATE[3] + ee + aaa) & 4294967295  # Update the third state variable with results from the right side.
    RIPEMD160_STATE[3] = (RIPEMD160_STATE[4] + aa + bbb) & 4294967295  # Update the fourth state variable.
    RIPEMD160_STATE[4] = (RIPEMD160_STATE[0] + bb + ccc) & 4294967295  # Update the fifth state variable with the rotated value from the left.
    RIPEMD160_STATE[0] = ddd  # Set the first state variable to the newly calculated ddd.

    return RIPEMD160_STATE  # Return the updated state after processing the message.

def RIPEMD160_bytes_to_int32_list(data):  # Convert a byte sequence to a list of 32-bit integers.
    return [int.from_bytes(data[i:i+4], 'little') for i in range(0, len(data), 4)]  # Create a list of integers by processing 4 bytes at a time.

def RIPEMD160_int32_to_bytes(n):  # Convert a 32-bit integer to a byte sequence.
    return n.to_bytes(4, 'little')  # Convert the integer to a byte representation in little-endian format.

def RIPEMD160_hash(message):
    """
    Compute the 160-bit RIPEMD-160 digest of a byte message.

    The message is padded to a multiple of 512 bits. A 1 bit is appended,
    then zero bits, then the original message length as a 64-bit
    little-endian integer. Each 512-bit block updates the five-word state.

    The final five 32-bit words form a 160-bit digest.
    """  # Main function to compute the RIPEMD-160 hash of the input message.
    RIPEMD160_STATE = [RIPEMD160_h0, RIPEMD160_h1, RIPEMD160_h2, RIPEMD160_h3, RIPEMD160_h4]  # Initialize the state with the initial hash values.

    if isinstance(message, str):  # Check if the message is a string.
        message = message.encode()  # Encode the string to bytes.

    original_byte_len = len(message)  # Get the length of the original message in bytes.
    message += bytes([128])  # Append a single '1' bit (128) to the message.
    message += bytes([0]) * ((56 - (original_byte_len + 1) % 64) % 64)  # Pad the message with zeros to make its length congruent to 56 modulo 64.
    message += (original_byte_len * 8).to_bytes(8, 'little')  # Append the original length of the message in bits, as a little-endian 64-bit integer.

    for i in range(0, len(message), 64):  # Process the message in 64-byte chunks.
        chunk = message[i:i+64]  # Get the current chunk of the message.
        X = RIPEMD160_bytes_to_int32_list(chunk)  # Convert the chunk to a list of 32-bit integers.
        RIPEMD160_STATE = RIPEMD160_compress(RIPEMD160_STATE, X)  # Update the RIPEMD160 state with the current chunk.

    result = b''.join(RIPEMD160_int32_to_bytes(x) for x in RIPEMD160_STATE)  # Convert the final state back to bytes by joining the 32-bit integers.
    return result  # Return the resulting hash as a byte sequence.

def hash160(data):
    """
    Bitcoin HASH160: RIPEMD160(SHA256(data)).

    First SHA-256 produces 256 bits. RIPEMD-160 then compresses that
    256-bit digest to 160 bits. Legacy P2PKH addresses encode this result.
    """  # Function to compute the HASH160, which is the RIPEMD-160 hash of the SHA-256 hash of the input data.
    return RIPEMD160_hash(sha256(data))  # Compute and return the RIPEMD-160 hash of the SHA-256 hash of the input data.





#######################################MAIN_FUNCTION####################################################################


def public_key_to_address(public_key, testnet=False):
    """
    Convert a serialized public key into a legacy P2PKH address.

    First calculate HASH160(public_key). Prefix the 20-byte result with
    version 0 for mainnet or 111 for testnet. Compute a four-byte checksum
    from double SHA-256 of that versioned payload. Append the checksum and
    Base58-encode the complete byte sequence.

    The checksum detects many transcription errors; it does not make the
    address secret or prove ownership.
    """
    # Step 1: reduce the public-key byte sequence to a 160-bit HASH160 value.
    # Step 1: Compute RIPEMD160(SHA256(public_key))
    public_key_hash = hash160(bytes.fromhex(public_key))
    
    # Step 2: Add version byte (0 for mainnet, 111 for testnet)
    versioned_hash = (b'\x6f' if testnet else bytes([0])) + public_key_hash
    
    # Step 3: Compute the checksum (first 4 bytes of double SHA256)
    checksum = double_sha256(versioned_hash)[:4]
    
    # Step 4: Concatenate versioned hash and checksum
    binary_address = versioned_hash + checksum
    
    # Step 5: Encode in Base58
    address = base58_encode(binary_address)
    
    return address


#######################################MAIN_FUNCTION_INPUT_OUTPUT##########################################################

def main():
    """Accept a decimal private-key integer and display a complete execution trace."""
    import sys
    import linecache

    print("=" * 78)
    print("BITCOIN ADDRESS GENERATION — LIVE MATHEMATICAL TRACE")
    print("Educational use only. Never enter a private key holding real funds.")
    print("Enter a decimal integer, for example: 1 or 14323423423")
    print("=" * 78)
    raw = input("Private key (decimal): ").strip()
    try:
        private_key_int = int(raw, 10)
    except ValueError:
        print("Invalid input: enter a whole decimal integer.")
        return

    # secp256k1 group order; valid private keys are in the interval [1, n-1].
    curve_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    print("\nSTEP 1 — PRIVATE INTEGER VALIDATION")
    print(f"d = {private_key_int}")
    print(f"Required mathematical condition: 1 <= d < n")
    print(f"n = {curve_order}")
    if not (1 <= private_key_int < curve_order):
        print("This is not a valid secp256k1 private-key integer.")
        return

    print("\nSTEP 2 — CURVE AND GENERATOR")
    print("Curve equation: y^2 = x^3 + 7 (mod p)")
    print(f"p = {prime}")
    print(f"G = ({generator_x}, {generator_y})")
    print("\nSTEP 3 — EXECUTING THE ORIGINAL MATHEMATICAL FUNCTIONS")
    print("For every executed line in the cryptographic functions, the program prints")
    print("the source formula/operation and the current numerical variables. This")
    print("includes point additions, scalar multiplication, SHA-256 rounds, RIPEMD-160")
    print("rounds, checksums, WIF construction, and Base58 long division.")

    traced_functions = {
        'point_addition', 'scalar_multiplication', 'to_uncompressed_hex',
        'to_compressed_hex', 'base58_encode', 'to_wif', 'sha256',
        'double_sha256', 'RIPEMD160_round', 'RIPEMD160_compress',
        'RIPEMD160_hash', 'hash160', 'public_key_to_address'
    }
    this_file = __file__
    previous_trace = sys.gettrace()

    def trace_math(frame, event, arg):
        if event == 'call':
            if frame.f_code.co_name in traced_functions and frame.f_code.co_filename == this_file:
                print("\n" + "-" * 78)
                print("MATHEMATICAL OPERATION:", frame.f_code.co_name)
                print("-" * 78)
                return trace_math
            return None
        if event == 'line' and frame.f_code.co_name in traced_functions and frame.f_code.co_filename == this_file:
            source_line = linecache.getline(this_file, frame.f_lineno).strip()
            if source_line and not source_line.startswith('#'):
                print(f"\n[{frame.f_code.co_name}, line {frame.f_lineno}] {source_line}")
                # Show the current numeric state; omit bulky lookup tables and byte arrays from locals.
                for name, value in frame.f_locals.items():
                    if name in {'self', 'func'}:
                        continue
                    if isinstance(value, (int, str, tuple)):
                        shown = repr(value)
                        if len(shown) > 500:
                            shown = shown[:500] + "..."
                        print(f"    {name} = {shown}")
                    elif isinstance(value, bytes):
                        print(f"    {name} = bytes({len(value)}): {value.hex()[:300]}{'...' if len(value) > 150 else ''}")
                    elif isinstance(value, list) and len(value) <= 20 and all(isinstance(x, int) for x in value):
                        print(f"    {name} = {value}")
            return trace_math
        return trace_math if frame.f_code.co_name in traced_functions else None

    try:
        sys.settrace(trace_math)
        generator_point = (generator_x, generator_y)
        public_key_point = scalar_multiplication(private_key_int, generator_point, prime)
        uncompressed_pub_key = to_uncompressed_hex(public_key_point)
        compressed_pub_key = to_compressed_hex(public_key_point)
        wif = to_wif(private_key_int)
        compressed_wif = to_wif(private_key_int, compressed=True)
        uncompressed_address = public_key_to_address(uncompressed_pub_key)
        compressed_address = public_key_to_address(compressed_pub_key)
    finally:
        sys.settrace(previous_trace)

    print("\n" + "=" * 78)
    print("FINAL BITCOIN RESULTS")
    print("=" * 78)
    print(f"Private key integer (decimal): {private_key_int}")
    print(f"Public-key point Q = dG: {public_key_point}")
    print(f"Uncompressed public key: {uncompressed_pub_key}")
    print(f"Compressed public key:   {compressed_pub_key}")
    print(f"Uncompressed WIF: {wif}")
    print(f"Compressed WIF:   {compressed_wif}")
    print(f"Uncompressed legacy P2PKH address: {uncompressed_address}")
    print(f"Compressed legacy P2PKH address:   {compressed_address}")
    print("\nThe trace shows each executed mathematical statement and its live variables.")


if __name__ == "__main__":
    main()
