#!/usr/bin/env python3
"""
BITCOIN ADDRESS GENERATION — PDF REPORT EDITION
================================================

Derives Bitcoin public keys, WIF private keys, and legacy P2PKH addresses
from a private key integer, then produces a professional multi-page PDF report.

Educational use only. Never enter a private key that controls real funds.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable, Preformatted
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib import colors
import io
from datetime import datetime, timezone

#########################################BTC_CONSTANTS####################################################################
prime = 115792089237316195423570985008687907853269984665640564039457584007908834671663
curve_a = 0
curve_b = 7
generator_x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
generator_y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
curve_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

#########################################Elliptic Curve Math################################################

def point_addition(point1, point2, prime):
    if point1 == (0, 0):
        return point2
    if point2 == (0, 0):
        return point1
    if point1 == point2:
        slope = (3 * point1[0]**2 + curve_a) * pow(2 * point1[1], prime - 2, prime) % prime
    else:
        slope = (point2[1] - point1[1]) * pow(point2[0] - point1[0], prime - 2, prime) % prime
    result_x = (slope * slope - point1[0] - point2[0]) % prime
    result_y = (slope * (point1[0] - result_x) - point1[1]) % prime
    return (result_x, result_y)

def scalar_multiplication(private_key, generator_point, prime):
    result = (0, 0)
    current_point = generator_point
    while private_key > 0:
        if private_key % 2 == 1:
            result = point_addition(result, current_point, prime)
        current_point = point_addition(current_point, current_point, prime)
        private_key //= 2
    return result

def to_uncompressed_hex(point):
    x, y = point
    return '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

def to_compressed_hex(point):
    x, y = point
    return ('02' if y % 2 == 0 else '03') + x.to_bytes(32, 'big').hex()

#######################################Base58 & WIF########################################################
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data):
    n = int.from_bytes(data, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(BASE58_ALPHABET[r])
    res = ''.join(res[::-1])
    pad = ''
    for byte in data:
        if byte == 0:
            pad += '1'
        else:
            break
    return pad + res

def to_wif(private_key, compressed=False, testnet=False):
    private_key_bytes = private_key.to_bytes(32, 'big')
    version = bytes([239]) if testnet else bytes([128])
    extended_key = version + private_key_bytes
    if compressed:
        extended_key += bytes([1])
    checksum = double_sha256(extended_key)[:4]
    binary = extended_key + checksum
    return base58_encode(binary)

#######################################SHA-256#############################################################
def rotr(x, n):
    return (x >> n) | (x << (32 - n)) & 4294967295

K = [
    1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993,
    2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987,
    1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774,
    264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
    2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
    113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
    1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411,
    3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
    430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
    1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
    2428436474, 2756734187, 3204031479, 3329325298
]

def sha256(data):
    if isinstance(data, str):
        data = data.encode()
    elif isinstance(data, int):
        data = data.to_bytes((data.bit_length() + 7) // 8, 'big')

    h0 = 1779033703
    h1 = 3144134277
    h2 = 1013904242
    h3 = 2773480762
    h4 = 1359893119
    h5 = 2600822924
    h6 = 528734635
    h7 = 1541459225

    length = len(data) * 8
    data += bytes([128])
    while (len(data) * 8 + 64) % 512 != 0:
        data += bytes([0])
    data += length.to_bytes(8, 'big')

    for chunk_start in range(0, len(data), 64):
        chunk = data[chunk_start:chunk_start + 64]
        w = [int.from_bytes(chunk[i:i + 4], 'big') for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 4294967295)

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for i in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & 4294967295
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 4294967295
            h = g
            g = f
            f = e
            e = (d + temp1) & 4294967295
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 4294967295

        h0 = (h0 + a) & 4294967295
        h1 = (h1 + b) & 4294967295
        h2 = (h2 + c) & 4294967295
        h3 = (h3 + d) & 4294967295
        h4 = (h4 + e) & 4294967295
        h5 = (h5 + f) & 4294967295
        h6 = (h6 + g) & 4294967295
        h7 = (h7 + h) & 4294967295

    return (h0.to_bytes(4, 'big') + h1.to_bytes(4, 'big') +
            h2.to_bytes(4, 'big') + h3.to_bytes(4, 'big') +
            h4.to_bytes(4, 'big') + h5.to_bytes(4, 'big') +
            h6.to_bytes(4, 'big') + h7.to_bytes(4, 'big'))

def double_sha256(data):
    return sha256(sha256(data))

#######################################RIPEMD-160##########################################################
RIPEMD160_CONSTANTS_ZERO_SQRT2 = [0, 1518500249, 1859775393, 2400959708, 2840853838]
RIPEMD160_CONSTANTS_SQRT3_ZERO = [1352829926, 1548603684, 1836072691, 2053994217, 0]
RIPEMD160_h0, RIPEMD160_h1, RIPEMD160_h2, RIPEMD160_h3, RIPEMD160_h4 = (
    1732584193, 4023233417, 2562383102, 271733878, 3285377520
)

RIPEMD160_r = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
]
RIPEMD160_r_prime = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
]
RIPEMD160_s = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]
RIPEMD160_s_prime = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]

def RIPEMD160_rotate_left(x, n):
    return ((x << n) | (x >> (32 - n))) & 4294967295

def RIPEMD160_xor(x, y, z):
    return x ^ y ^ z

def RIPEMD160_conditional(x, y, z):
    return (x & y) | (~x & z)

def RIPEMD160_majority_with_twist(x, y, z):
    return (x | ~y) ^ z

def RIPEMD160_conditional_inverse(x, y, z):
    return (x & z) | (y & ~z)

def RIPEMD160_xor_or_complement(x, y, z):
    return x ^ (y | ~z)

def RIPEMD160_round(a, b, c, d, e, x, s, k, func):
    a = (a + func(b, c, d) + x + k) & 4294967295
    a = RIPEMD160_rotate_left(a, s) + e
    c = RIPEMD160_rotate_left(c, 10)
    return a & 4294967295, c & 4294967295

def RIPEMD160_compress(RIPEMD160_STATE, X):
    aa, bb, cc, dd, ee = RIPEMD160_STATE
    aaa, bbb, ccc, ddd, eee = RIPEMD160_STATE

    for j in range(80):
        if j < 16:
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[0], RIPEMD160_xor)
        elif j < 32:
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[1], RIPEMD160_conditional)
        elif j < 48:
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[2], RIPEMD160_majority_with_twist)
        elif j < 64:
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[3], RIPEMD160_conditional_inverse)
        else:
            aa, cc = RIPEMD160_round(aa, bb, cc, dd, ee, X[RIPEMD160_r[j]], RIPEMD160_s[j], RIPEMD160_CONSTANTS_ZERO_SQRT2[4], RIPEMD160_xor_or_complement)
        aa, bb, cc, dd, ee = ee, aa, bb, cc, dd

    for j in range(80):
        if j < 16:
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[0], RIPEMD160_xor_or_complement)
        elif j < 32:
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[1], RIPEMD160_conditional_inverse)
        elif j < 48:
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[2], RIPEMD160_majority_with_twist)
        elif j < 64:
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[3], RIPEMD160_conditional)
        else:
            aaa, ccc = RIPEMD160_round(aaa, bbb, ccc, ddd, eee, X[RIPEMD160_r_prime[j]], RIPEMD160_s_prime[j], RIPEMD160_CONSTANTS_SQRT3_ZERO[4], RIPEMD160_xor)
        aaa, bbb, ccc, ddd, eee = eee, aaa, bbb, ccc, ddd

    ddd = (RIPEMD160_STATE[1] + cc + ddd) & 4294967295
    RIPEMD160_STATE[1] = (RIPEMD160_STATE[2] + dd + eee) & 4294967295
    RIPEMD160_STATE[2] = (RIPEMD160_STATE[3] + ee + aaa) & 4294967295
    RIPEMD160_STATE[3] = (RIPEMD160_STATE[4] + aa + bbb) & 4294967295
    RIPEMD160_STATE[4] = (RIPEMD160_STATE[0] + bb + ccc) & 4294967295
    RIPEMD160_STATE[0] = ddd
    return RIPEMD160_STATE

def RIPEMD160_bytes_to_int32_list(data):
    return [int.from_bytes(data[i:i+4], 'little') for i in range(0, len(data), 4)]

def RIPEMD160_int32_to_bytes(n):
    return n.to_bytes(4, 'little')

def RIPEMD160_hash(message):
    RIPEMD160_STATE = [RIPEMD160_h0, RIPEMD160_h1, RIPEMD160_h2, RIPEMD160_h3, RIPEMD160_h4]
    if isinstance(message, str):
        message = message.encode()
    original_byte_len = len(message)
    message += bytes([128])
    message += bytes([0]) * ((56 - (original_byte_len + 1) % 64) % 64)
    message += (original_byte_len * 8).to_bytes(8, 'little')
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        X = RIPEMD160_bytes_to_int32_list(chunk)
        RIPEMD160_STATE = RIPEMD160_compress(RIPEMD160_STATE, X)
    return b''.join(RIPEMD160_int32_to_bytes(x) for x in RIPEMD160_STATE)

def hash160(data):
    return RIPEMD160_hash(sha256(data))

#######################################Address#############################################################
def public_key_to_address(public_key, testnet=False):
    public_key_hash = hash160(bytes.fromhex(public_key))
    versioned_hash = (b'\x6f' if testnet else bytes([0])) + public_key_hash
    checksum = double_sha256(versioned_hash)[:4]
    binary_address = versioned_hash + checksum
    return base58_encode(binary_address)

#######################################PDF Generation######################################################

def create_pdf_report(private_key_int, public_key_point, uncompressed_pub_key,
                      compressed_pub_key, wif, compressed_wif,
                      uncompressed_address, compressed_address,
                      output_path="bitcoin_address_report.pdf"):
    """Generate a professional multi-page PDF report of the Bitcoin derivation."""

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18*mm,
        leftMargin=18*mm,
        topMargin=16*mm,
        bottomMargin=16*mm
    )

    # Colors
    orange = HexColor("#F7931A")
    dark = HexColor("#1A1A2E")
    mid = HexColor("#16213E")
    light_bg = HexColor("#F8F9FA")
    code_bg = HexColor("#EEF2F7")
    warning_bg = HexColor("#FFF3CD")
    warning_border = HexColor("#FFC107")

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(
        name="MainTitle",
        fontName="Helvetica-Bold",
        fontSize=18,
        textColor=dark,
        alignment=TA_CENTER,
        spaceAfter=4*mm,
        leading=22
    ))
    styles.add(ParagraphStyle(
        name="SubTitle",
        fontName="Helvetica",
        fontSize=10,
        textColor=HexColor("#555555"),
        alignment=TA_CENTER,
        spaceAfter=6*mm
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader",
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=orange,
        spaceBefore=6*mm,
        spaceAfter=3*mm,
        borderPadding=2
    ))
    styles.add(ParagraphStyle(
        name="BodyText2",
        fontName="Helvetica",
        fontSize=9,
        textColor=dark,
        alignment=TA_JUSTIFY,
        spaceAfter=2*mm,
        leading=12
    ))
    styles.add(ParagraphStyle(
        name="Mono",
        fontName="Courier",
        fontSize=7.5,
        textColor=dark,
        leading=10,
        spaceAfter=1*mm
    ))
    styles.add(ParagraphStyle(
        name="MonoSmall",
        fontName="Courier",
        fontSize=6.5,
        textColor=dark,
        leading=8.5,
        spaceAfter=1*mm
    ))
    styles.add(ParagraphStyle(
        name="Label",
        fontName="Helvetica-Bold",
        fontSize=8,
        textColor=HexColor("#444444"),
        spaceBefore=2*mm,
        spaceAfter=1*mm
    ))
    styles.add(ParagraphStyle(
        name="Warning",
        fontName="Helvetica",
        fontSize=8,
        textColor=HexColor("#856404"),
        leading=11,
        alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name="Footer",
        fontName="Helvetica",
        fontSize=7,
        textColor=HexColor("#888888"),
        alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name="Math",
        fontName="Courier",
        fontSize=8,
        textColor=dark,
        leading=11,
        leftIndent=4*mm,
        spaceAfter=1.5*mm
    ))

    story = []

    # ========== TITLE ==========
    story.append(Paragraph("BITCOIN ADDRESS GENERATION", styles["MainTitle"]))
    story.append(Paragraph("Mathematical Derivation Report — Educational Edition", styles["SubTitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=orange, spaceAfter=3*mm))

    # Warning box
    warning_data = [[Paragraph(
        "<b>SECURITY WARNING</b><br/>"
        "A real private key controls funds. Never paste a real private key into an "
        "untrusted computer, website, or shared environment. This report is for "
        "mathematical study only.",
        styles["Warning"]
    )]]
    warning_table = Table(warning_data, colWidths=[170*mm])
    warning_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), warning_bg),
        ("BOX", (0, 0), (-1, -1), 1.5, warning_border),
        ("TOPPADDING", (0, 0), (-1, -1), 4*mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4*mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 4*mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4*mm),
    ]))
    story.append(warning_table)
    story.append(Spacer(1, 5*mm))

    # ========== STEP 1: PRIVATE KEY ==========
    story.append(Paragraph("1. Private Key Validation", styles["SectionHeader"]))
    story.append(Paragraph(
        "A valid secp256k1 private key is an integer <b>d</b> satisfying "
        "<font face='Courier'>1 ≤ d &lt; n</font>, where <b>n</b> is the order of the generator point G.",
        styles["BodyText2"]
    ))
    story.append(Paragraph("Private key integer (decimal):", styles["Label"]))
    story.append(Paragraph(str(private_key_int), styles["Mono"]))
    story.append(Paragraph("Group order n:", styles["Label"]))
    story.append(Paragraph(str(curve_order), styles["MonoSmall"]))
    story.append(Paragraph(
        f"<b>Status:</b> Valid — 1 ≤ d &lt; n is satisfied.",
        styles["BodyText2"]
    ))

    # ========== STEP 2: CURVE ==========
    story.append(Paragraph("2. Elliptic Curve Parameters (secp256k1)", styles["SectionHeader"]))
    story.append(Paragraph(
        "Bitcoin uses the elliptic curve defined over the finite field F<sub>p</sub> by the equation:",
        styles["BodyText2"]
    ))
    story.append(Paragraph("y² ≡ x³ + 7  (mod p)", styles["Math"]))
    story.append(Paragraph("Field prime p:", styles["Label"]))
    story.append(Paragraph(str(prime), styles["MonoSmall"]))
    story.append(Paragraph("Generator point G = (Gx, Gy):", styles["Label"]))
    story.append(Paragraph(f"Gx = {generator_x}", styles["MonoSmall"]))
    story.append(Paragraph(f"Gy = {generator_y}", styles["MonoSmall"]))

    # ========== STEP 3: PUBLIC KEY ==========
    story.append(Paragraph("3. Public Key Derivation — Scalar Multiplication Q = d·G", styles["SectionHeader"]))
    story.append(Paragraph(
        "The public key is the elliptic-curve point obtained by adding the generator G to itself "
        "exactly <b>d</b> times. This is computed efficiently via the binary double-and-add algorithm:",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        "Write d in binary. Successively form G, 2G, 4G, 8G, … by point doubling. "
        "Whenever the corresponding bit of d is 1, accumulate that multiple into the result.",
        styles["BodyText2"]
    ))
    story.append(Paragraph("Resulting public-key point Q = (Qx, Qy):", styles["Label"]))
    story.append(Paragraph(f"Qx = {public_key_point[0]}", styles["MonoSmall"]))
    story.append(Paragraph(f"Qy = {public_key_point[1]}", styles["MonoSmall"]))

    # ========== STEP 4: SERIALIZATION ==========
    story.append(Paragraph("4. Public Key Serialization (SEC format)", styles["SectionHeader"]))
    story.append(Paragraph(
        "<b>Uncompressed</b> format: 04 ‖ X ‖ Y  (65 bytes). "
        "Both coordinates are encoded as 32-byte big-endian integers.",
        styles["BodyText2"]
    ))
    story.append(Paragraph("Uncompressed public key:", styles["Label"]))
    # Split long hex into chunks for readability
    unc = uncompressed_pub_key
    for i in range(0, len(unc), 64):
        story.append(Paragraph(unc[i:i+64], styles["MonoSmall"]))

    story.append(Paragraph(
        "<b>Compressed</b> format: 02 ‖ X  (if Y even) or 03 ‖ X  (if Y odd) — 33 bytes. "
        "The curve equation recovers ±Y from X; the prefix selects the correct parity.",
        styles["BodyText2"]
    ))
    story.append(Paragraph("Compressed public key:", styles["Label"]))
    story.append(Paragraph(compressed_pub_key, styles["Mono"]))

    # ========== STEP 5: WIF ==========
    story.append(Paragraph("5. Wallet Import Format (WIF)", styles["SectionHeader"]))
    story.append(Paragraph(
        "WIF encodes the private key for human-readable backup. Construction:",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        "1. Version byte (0x80 mainnet) + 32-byte private key (+ 0x01 if compressed)<br/>"
        "2. Checksum = first 4 bytes of SHA256(SHA256(payload))<br/>"
        "3. Base58-encode the concatenation of payload and checksum",
        styles["BodyText2"]
    ))
    story.append(Paragraph("Uncompressed WIF:", styles["Label"]))
    story.append(Paragraph(wif, styles["Mono"]))
    story.append(Paragraph("Compressed WIF:", styles["Label"]))
    story.append(Paragraph(compressed_wif, styles["Mono"]))

    # ========== STEP 6: ADDRESS ==========
    story.append(Paragraph("6. Legacy P2PKH Address (Base58Check)", styles["SectionHeader"]))
    story.append(Paragraph(
        "A Pay-to-Public-Key-Hash address is formed as follows:",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        "1. HASH160 = RIPEMD160(SHA256(serialized public key))  → 20 bytes<br/>"
        "2. Version byte 0x00 (mainnet) ‖ HASH160<br/>"
        "3. Checksum = first 4 bytes of SHA256(SHA256(versioned payload))<br/>"
        "4. Base58-encode the 25-byte result",
        styles["BodyText2"]
    ))
    story.append(Paragraph("Uncompressed legacy address:", styles["Label"]))
    story.append(Paragraph(uncompressed_address, styles["Mono"]))
    story.append(Paragraph("Compressed legacy address:", styles["Label"]))
    story.append(Paragraph(compressed_address, styles["Mono"]))

    # ========== SUMMARY TABLE ==========
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("7. Summary of Final Results", styles["SectionHeader"]))

    def cell(text, style="MonoSmall"):
        return Paragraph(str(text), styles[style])

    summary_data = [
        [Paragraph("<b>Item</b>", styles["Label"]), Paragraph("<b>Value</b>", styles["Label"])],
        [cell("Private key (decimal)", "Label"), cell(private_key_int)],
        [cell("Public key point Qx", "Label"), cell(public_key_point[0])],
        [cell("Public key point Qy", "Label"), cell(public_key_point[1])],
        [cell("Uncompressed pubkey", "Label"), cell(uncompressed_pub_key[:40] + "…")],
        [cell("Compressed pubkey", "Label"), cell(compressed_pub_key)],
        [cell("Uncompressed WIF", "Label"), cell(wif)],
        [cell("Compressed WIF", "Label"), cell(compressed_wif)],
        [cell("Uncompressed address", "Label"), cell(uncompressed_address)],
        [cell("Compressed address", "Label"), cell(compressed_address)],
    ]

    summary_table = Table(summary_data, colWidths=[45*mm, 125*mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#E8E8E8")),
        ("BACKGROUND", (0, 1), (-1, -1), light_bg),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, HexColor("#DDDDDD")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2*mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2*mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 2*mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2*mm),
    ]))
    story.append(summary_table)

    # ========== MATHEMATICAL NOTES ==========
    story.append(PageBreak())
    story.append(Paragraph("Appendix — Mathematical Notes", styles["SectionHeader"]))
    story.append(Paragraph(
        "<b>Elliptic-curve group law.</b> Points on the curve form an abelian group. "
        "The identity is the point at infinity (represented here as (0,0)). "
        "Point addition of distinct points P and R uses the slope "
        "m = (y<sub>R</sub> − y<sub>P</sub>) · (x<sub>R</sub> − x<sub>P</sub>)<sup>−1</sup> (mod p). "
        "Point doubling uses the tangent slope m = (3x²) · (2y)<sup>−1</sup> (mod p). "
        "Modular inverses are obtained via Fermat’s little theorem: z<sup>−1</sup> ≡ z<sup>p−2</sup> (mod p).",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        "<b>SHA-256.</b> A cryptographic hash that maps arbitrary-length input to a 256-bit digest. "
        "It pads the message, processes 512-bit blocks, expands each block into 64 words, "
        "and performs 64 rounds of bitwise mixing (rotations, XOR, choice, majority) "
        "with modular 2³² addition.",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        "<b>RIPEMD-160.</b> A 160-bit hash used by Bitcoin after SHA-256. "
        "It processes 512-bit blocks with two parallel lines of 80 rounds each, "
        "using different Boolean functions, message schedules, and constants, "
        "then recombines the lines.",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        "<b>Base58Check.</b> An encoding that avoids visually ambiguous characters "
        "(0, O, I, l) and appends a 4-byte checksum derived from double-SHA-256. "
        "It is an encoding, not a hash or encryption.",
        styles["BodyText2"]
    ))
    story.append(Paragraph(
        "<b>HASH160.</b> The composition RIPEMD160(SHA256(·)) that reduces a public key "
        "to a 20-byte identifier used in legacy P2PKH addresses.",
        styles["BodyText2"]
    ))

    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC")))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
        "Educational software only · Not for production use with real funds",
        styles["Footer"]
    ))

    doc.build(story)
    return output_path

#######################################MAIN################################################################

def main():
    print("=" * 70)
    print("BITCOIN ADDRESS GENERATION — PDF REPORT EDITION")
    print("Educational use only. Never enter a private key holding real funds.")
    print("=" * 70)

    import sys
    if len(sys.argv) > 1:
        raw = sys.argv[1]
    else:
        raw = input("Private key (decimal integer): ").strip()

    try:
        private_key_int = int(raw, 10)
    except ValueError:
        print("Invalid input: enter a whole decimal integer.")
        return

    if not (1 <= private_key_int < curve_order):
        print("This is not a valid secp256k1 private-key integer (must satisfy 1 ≤ d < n).")
        return

    print("\nComputing elliptic-curve scalar multiplication Q = d·G …")
    generator_point = (generator_x, generator_y)
    public_key_point = scalar_multiplication(private_key_int, generator_point, prime)

    print("Serializing public keys …")
    uncompressed_pub_key = to_uncompressed_hex(public_key_point)
    compressed_pub_key = to_compressed_hex(public_key_point)

    print("Generating WIF …")
    wif = to_wif(private_key_int)
    compressed_wif = to_wif(private_key_int, compressed=True)

    print("Deriving addresses …")
    uncompressed_address = public_key_to_address(uncompressed_pub_key)
    compressed_address = public_key_to_address(compressed_pub_key)

    # Console summary
    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    print(f"Private key (decimal): {private_key_int}")
    print(f"Public key point Q:    ({public_key_point[0]}, {public_key_point[1]})")
    print(f"Uncompressed pubkey:   {uncompressed_pub_key}")
    print(f"Compressed pubkey:     {compressed_pub_key}")
    print(f"Uncompressed WIF:      {wif}")
    print(f"Compressed WIF:        {compressed_wif}")
    print(f"Uncompressed address:  {uncompressed_address}")
    print(f"Compressed address:    {compressed_address}")

    # Generate PDF
    out_path = "bitcoin_address_report.pdf"
    print(f"\nGenerating PDF report → {out_path}")
    create_pdf_report(
        private_key_int, public_key_point,
        uncompressed_pub_key, compressed_pub_key,
        wif, compressed_wif,
        uncompressed_address, compressed_address,
        output_path=out_path
    )
    print(f"PDF written successfully: {out_path}")
    print("Done.")

if __name__ == "__main__":
    main()
