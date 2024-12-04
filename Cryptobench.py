# Cryptobench 1.0
#
# Version Created by: Omar Ramadan
# Date: 30/11/2024
#
# Includes the benchmarking, comparison and evaluation of the following cryptographic algorithms:
# RSA, DSA and ECC Keypair Generation
# RSA Encryption and Decryption
# RSA, DSA and ECC Digital Signature Generation and Verification
#
# Across the following bit sizes:
# 80, 112, 128, 192 and 256 bits [Symmetric Scheme]
#
# 512, 1024, 2048, 3072 and 15360 bits [RSA/DSA]
#
# 112, 160, 224, 256, 384 and 512 bits [ECC] 

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
import os
import time

# Number of repetitions, you need to omit the first set of results
num_repeats = 11

for i in range(num_repeats):

    # RSA Section ( 80 bits )
    # RSA Keypair Generation

    # timer

    before80rkg = time.perf_counter()

    # private-key of 80 bits.
    private_key80 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )

    private_key_str80 = private_key80.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # public-key
    public_key80 = private_key80.public_key()

    public_key_str80 = public_key80.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.PKCS1
    )

    after80rkg = time.perf_counter()
    print(f"{after80rkg - before80rkg:0.4f} seconds for rsa 80 bit keypair generation") # put these 2 lines after code you want to time

    # RSA Encryption ( 80 bits )

    before80re = time.perf_counter()

    short_plaintext = os.urandom(50)

    short_ciphertext = public_key80.encrypt(
        short_plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after80re = time.perf_counter()
    print(f"{after80re - before80re:0.4f} seconds for rsa 80 bit encryption") # put these 2 lines after code you want to time

    # RSA Decryption ( 80 bits )

    before80rd = time.perf_counter()

    short_plaintext_2 = private_key80.decrypt(
        short_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after80rd = time.perf_counter()
    print(f"{after80rd - before80rd:0.4f} seconds for rsa 80 bit decryption") # put these 2 lines after code you want to time

    # RSA Digital Signature Generation

    before80rsg = time.perf_counter()
    # We can sign the message using "hash-then-sign".
    signature = private_key80.sign(
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after80rsg = time.perf_counter()
    print(f"{after80rsg - before80rsg:0.4f} seconds for rsa 80 bit signature generation") # put these 2 lines after code you want to time

    # RSA Digital Signature Verification

    before80rsv1 = time.perf_counter()
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key80.verify(
        signature,
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after80rsv1 = time.perf_counter()
    print(f"{after80rsv1 - before80rsv1:0.4f} seconds for rsa 80 bit signature verification") # put these 2 lines after code you want to time

    # RSA Section ( 112 bits )
    # RSA Keypair Generation

    before112rkg = time.perf_counter()

    # private-key of 112 bits.
    private_key112 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_key_str112 = private_key112.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # public-key
    public_key112 = private_key112.public_key()

    public_key_str112 = public_key112.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.PKCS1
    )

    after112rkg = time.perf_counter()
    print(f"{after112rkg - before112rkg:0.4f} seconds for 112 bit rsa keypair generation") # put these 2 lines after code you want to time

    # RSA Encryption ( 112 bits )

    before112re = time.perf_counter()
    short_ciphertext = public_key112.encrypt(
        short_plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after112re = time.perf_counter()
    print(f"{after112re - before112re:0.4f} seconds for 112 bit rsa encryption") # put these 2 lines after code you want to time

    # RSA Decryption ( 112 bits )

    before112d = time.perf_counter()
    short_plaintext_2 = private_key112.decrypt(
        short_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after112d = time.perf_counter()
    print(f"{after112d - before112d:0.4f} seconds for 112 bit rsa decryption") # put these 2 lines after code you want to time

    # RSA Digital Signature Generation

    before112rsg = time.perf_counter()

    # We can sign the message using "hash-then-sign".
    signature = private_key112.sign(
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after112rsg = time.perf_counter()
    print(f"{after112rsg - before112rsg:0.4f} seconds for 112 bit rsa signature generation") # put these 2 lines after code you want to time

    # RSA Digital Signature Verification

    before112sv1 = time.perf_counter()
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key112.verify(
        signature,
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after112sv1 = time.perf_counter()
    print(f"{after112sv1 - before112sv1:0.4f} seconds for 112 bit rsa signature verification") # put these 2 lines after code you want to time

    # RSA Section ( 128 bits )
    # RSA Keypair Generation

    before128rkg = time.perf_counter()
    # private-key of 128 bits.
    private_key128 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    private_key_str128 = private_key128.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # public-key
    public_key128 = private_key128.public_key()

    public_key_str128 = public_key128.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.PKCS1
    )

    after128rkg = time.perf_counter()
    print(f"{after128rkg - before128rkg:0.4f} seconds for 128 bit rsa keypair generation") # put these 2 lines after code you want to time

    # RSA Encryption ( 128 bits )

    before128re = time.perf_counter()
    short_ciphertext = public_key128.encrypt(
        short_plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after128re = time.perf_counter()
    print(f"{after128re - before128re:0.4f} seconds for 128 bit rsa encryption") # put these 2 lines after code you want to time

    # RSA Decryption ( 128 bits )

    before128rd = time.perf_counter()
    short_plaintext_2 = private_key128.decrypt(
        short_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after128rd = time.perf_counter()
    print(f"{after128rd - before128rd:0.4f} seconds for 128 bit rsa decryption") # put these 2 lines after code you want to time

    # RSA Digital Signature Generation

    before128rsg = time.perf_counter()
    # We can sign the message using "hash-then-sign".
    signature = private_key128.sign(
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after128rsg = time.perf_counter()
    print(f"{after128rsg - before128rsg:0.4f} seconds for 128 bit rsa signature generation") # put these 2 lines after code you want to time

    # RSA Digital Signature Verification

    before128rsv1 = time.perf_counter()

    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key128.verify(
        signature,
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after128rsv1 = time.perf_counter()
    print(f"{after128rsv1 - before128rsv1:0.4f} seconds for 128 bit rsa signature verification") # put these 2 lines after code you want to time

    # RSA Section ( 192 bits )
    # RSA Keypair Generation

    before192rkg = time.perf_counter()

    # private-key of 192 bits.
    private_key192 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=7680
    )

    private_key_str192 = private_key192.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # public-key
    public_key192 = private_key192.public_key()

    public_key_str192 = public_key80.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.PKCS1
    )

    after192rkg = time.perf_counter()
    print(f"{after192rkg - before192rkg:0.4f} seconds for 192 bit rsa keypair generation") # put these 2 lines after code you want to time

    # RSA Encryption ( 192 bits )

    before192re = time.perf_counter()
    short_ciphertext = public_key192.encrypt(
        short_plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    after192re = time.perf_counter()
    print(f"{after192re - before192re:0.4f} seconds for 192 bit rsa encryption") # put these 2 lines after code you want to time

    # RSA Decryption ( 192 bits )

    before192rd = time.perf_counter()
    short_plaintext_2 = private_key192.decrypt(
        short_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after192rd = time.perf_counter()
    print(f"{after192rd - before192rd:0.4f} seconds for 192 bit rsa decryption") # put these 2 lines after code you want to time


    # RSA Digital Signature Generation
    before192rsg = time.perf_counter()
    # We can sign the message using "hash-then-sign".
    signature = private_key192.sign(
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after192rsg = time.perf_counter()
    print(f"{after192rsg - before192rsg:0.4f} seconds for 192 bit rsa signature generation") # put these 2 lines after code you want to time

    # RSA Digital Signature Verification

    before192rsv1 = time.perf_counter()
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key192.verify(
        signature,
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after192rsv1 = time.perf_counter()
    print(f"{after192rsv1 - before192rsv1:0.4f} seconds for 192 bit signature verification") # put these 2 lines after code you want to time
    # RSA Section ( 256 bits )
    # RSA Keypair Generation

    before256rkg = time.perf_counter()
    # private-key of 256 bits.
    private_key256 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=15360
    )

    private_key_str256 = private_key256.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # public-key
    public_key256 = private_key256.public_key()

    public_key_str256 = public_key256.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.PKCS1
    )


    after256rkg = time.perf_counter()
    print(f"{after256rkg - before256rkg:0.4f} seconds for rsa 256 bit keypair generation") # put these 2 lines after code you want to time

    # RSA Encryption ( 256 bits )

    before256re = time.perf_counter()

    short_ciphertext = public_key256.encrypt(
        short_plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after256re = time.perf_counter()
    print(f"{after256re - before256re:0.4f} seconds for rsa 256 bit encryotion") # put these 2 lines after code you want to time

    # RSA Decryption ( 256 bits )

    before256rd = time.perf_counter()
    short_plaintext_2 = private_key256.decrypt(
        short_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    after256rd = time.perf_counter()
    print(f"{after256rd - before256rd:0.4f} seconds for 256 bit rsa decryption") # put these 2 lines after code you want to time

    # RSA Digital Signature Generation

    before256rsg = time.perf_counter()
    # We can sign the message using "hash-then-sign".
    signature = private_key256.sign(
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after256rsg = time.perf_counter()
    print(f"{after256rsg - before256rsg:0.4f} seconds for 256 bit rsa signature generation") # put these 2 lines after code you want to time

    # RSA Digital Signature Verification

    before256rsv1 = time.perf_counter()
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key256.verify(
        signature,
        short_plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    after256rsv1 = time.perf_counter()
    print(f"{after256rsv1 - before256rsv1:0.4f} seconds for 256 bit signature verification") # put these 2 lines after code you want to time

    # DSA Section ( 80 bits )
    # DSA Keypair Generation

    before80dkg = time.perf_counter()
    # private-key
    private_key80d = dsa.generate_private_key(
        key_size=1024
    )

    # public-key.
    public_key80d = private_key80d.public_key()

    after80dkg = time.perf_counter()
    print(f"{after80dkg - before80dkg:0.4f} seconds for 80 bit keypair generation") # put these 2 lines after code you want to time

    # DSA Digital Signing 
    before80dds = time.perf_counter()
    # We can sign the message using "hash-then-sign".
    signature = private_key80d.sign(
        short_plaintext,
        hashes.SHA256()
    )

    after80dds = time.perf_counter()
    print(f"{after80dds - before80dds:0.4f} seconds for 80 bit dsa signature generation") # put these 2 lines after code you want to time

    # DSA Signature Verification

    before80dsv1 = time.perf_counter()
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key80d.verify(
        signature,
        short_plaintext,
        hashes.SHA256()
    )

    after80dsv1 = time.perf_counter()
    print(f"{after80dsv1 - before80dsv1:0.4f} seconds for 80 bit dsa signature verification") # put these 2 lines after code you want to time

    # DSA Section ( 112 bits )
    # DSA Keypair Generation

    before112dkg = time.perf_counter()
    # private-key
    private_key112d = dsa.generate_private_key(
        key_size=2048
    )

    # public-key.
    public_key112d = private_key112d.public_key()

    after112dkg = time.perf_counter()
    print(f"{after112dkg - before112dkg:0.4f} seconds for 112 bit dsa keypair generation") # put these 2 lines after code you want to time

    # DSA Digital Signing 

    before112dds = time.perf_counter()
    # We can sign the message using "hash-then-sign".
    signature = private_key112d.sign(
        short_plaintext,
        hashes.SHA256()
    )

    after112dds = time.perf_counter()
    print(f"{after112dds - before112dds:0.4f} seconds for 112 bit dsa signature generation") # put these 2 lines after code you want to time

    # DSA Signature Verification

    befored128dsv1 = time.perf_counter()
    
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key112d.verify(
        signature,
        short_plaintext,
        hashes.SHA256()
    )

    after128dsv1 = time.perf_counter()  
    print(f"{after128dsv1 - befored128dsv1:0.4f} seconds for 112 bit signature verification") # put these 2 lines after code you want to time

    # DSA Section ( 128 bits )
    # DSA Keypair Generation

    before128dkg = time.perf_counter()
    # private-key
    private_key128d = dsa.generate_private_key(
        key_size=3072
    )

    # public-key.
    public_key128d = private_key128d.public_key()

    after128dkg = time.perf_counter()
    print(f"{after128dkg - before128dkg:0.4f} seconds for 128 bit dsa keypair generation") # put these 2 lines after code you want to time
    # DSA Digital Signing 

    before128ds = time.perf_counter()
    # We can sign the message using "hash-then-sign".
    signature = private_key128d.sign(
        short_plaintext,
        hashes.SHA256()
    )

    after128ds = time.perf_counter()
    print(f"{after128ds - before128ds:0.4f} seconds for 128 bit dsa signature generation") # put these 2 lines after code you want to time
    # DSA Signature Verification

    before128dsv1 = time.perf_counter()
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.
    public_key128d.verify(
        signature,
        short_plaintext,
        hashes.SHA256()
    )

    after128dsv1 = time.perf_counter()
    print(f"{after128dsv1 - before128dsv1:0.4f} seconds for 128 bit dsa signature verification") # put these 2 lines after code you want to time

    # ECC Section ( 80 bits)
    # ECC Keypair Generation
    
    # Curve options for different key sizes:
    # ec.SECP192R1()  # ~80-bit security
    # ec.SECP224R1()  # ~112-bit security
    # ec.SECP256R1()  # ~128-bit security
    # ec.SECP384R1()  # ~192-bit security
    # ec.SECP521R1()  # ~256-bit security

    before80ekg = time.perf_counter()

    # private-key
    private_key80e = ec.generate_private_key(
        ec.SECP192R1()
    )

    # public-key.
    public_key80e = private_key80e.public_key()

    after80ekg = time.perf_counter()
    print(f"{after80ekg - before80ekg:0.4f} seconds for 80 bit ecc keypair generation") # put these 2 lines after code you want to time

    # ECC Digital Signing
    # We can sign the message using "hash-then-sign".

    before80eds = time.perf_counter() 

    signature = private_key80e.sign(
       short_plaintext,
   ec.ECDSA(hashes.SHA256())
    )

    after80eds = time.perf_counter()
    print(f"{after80eds - before80eds:0.4f} seconds for 80 bit ecc signature generation") # put these 2 lines after code you want to time

    # ECC Digital Signature Verification
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.

    before80esv1 = time.perf_counter()

    public_key80e.verify(
        signature,
        short_plaintext,
        ec.ECDSA(hashes.SHA256())
    )

    after80esv1 = time.perf_counter()
    print(f"{after80esv1 - before80esv1:0.4f} seconds for 80 bit ecc signature verification") # put these 2 lines after code you want to time

    # ECC Section ( 112 bits)
    # ECC Keypair Generation

    before112ekg = time.perf_counter()

    # private-key
    private_key224e = ec.generate_private_key(
        ec.SECP224R1()
    )

    # public-key.
    public_key224e = private_key224e.public_key()

    after112ekg = time.perf_counter()
    print(f"{after112ekg - before112ekg:0.4f} seconds for 112 bit ecc keypair generation") # put these 2 lines after code you want to time


    # ECC Digital Signing
    # We can sign the message using "hash-then-sign".

    before112eds = time.perf_counter()
    signature = private_key224e.sign(
        short_plaintext,
        ec.ECDSA(hashes.SHA256())
    )

    after112eds = time.perf_counter()
    print(f"{after112eds - before112eds:0.4f} seconds for 112 bit ecc signature generation") # put these 2 lines after code you want to time

    # ECC Digital Signature Verification
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.

    before112edsv1 = time.perf_counter()

    public_key224e.verify(
        signature,
        short_plaintext,
        ec.ECDSA(hashes.SHA256())
    )

    after112edsv1 = time.perf_counter()
    print(f"{after112edsv1 - before112edsv1:0.4f} seconds for 112 bit ecc signature verification") # put these 2 lines after code you want to time

    # ECC Section ( 128 bits)
    # ECC Keypair Generation

    before128ekg = time.perf_counter()

    # private-key
    private_key256e = ec.generate_private_key(
        ec.SECP256R1()
    )

    # public-key.
    public_key256e = private_key256e.public_key()

    after128ekg = time.perf_counter()
    print(f"{after128ekg - before128ekg:0.4f} seconds for 128 bit ecc keypair generation") # put these 2 lines after

    # ECC Digital Signing
    # We can sign the message using "hash-then-sign".

    before128eds = time.perf_counter()

    signature = private_key256e.sign(
    short_plaintext,
        ec.ECDSA(hashes.SHA256())
    )

    after128eds = time.perf_counter()
    print(f"{after128eds - before128eds:0.4f} seconds for 128 bit ecc signature generation") # put these 2 lines after code you want to time

    # ECC Digital Signature Verification
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.

    before128edsv1 = time.perf_counter()

    public_key256e.verify(
        signature,
        short_plaintext,
        ec.ECDSA(hashes.SHA256())
    )

    afteredsv1 = time.perf_counter()
    print(f"{afteredsv1 - before128edsv1:0.4f} seconds for 128 bit ecc signature verification") # put these 2 lines after code you want to time

    # ECC Section ( 192 bits)
    # ECC Keypair Generation

    before192ekg = time.perf_counter()

    # private-key
    private_key384e = ec.generate_private_key(
        ec.SECP384R1()
    )

    # public-key.
    public_key384e = private_key384e.public_key()

    after192ekg = time.perf_counter()
    print(f"{after192ekg - before192ekg:0.4f} seconds for 192 bit ecc keypair generation") # put these 2 lines after code you want to time

    # ECC Digital Signing
    # We can sign the message using "hash-then-sign".

    before192eds = time.perf_counter()

    signature = private_key384e.sign(
        short_plaintext,
        ec.ECDSA(hashes.SHA256())
    )

    after192eds = time.perf_counter()
    print(f"{after192eds - before192eds:0.4f} seconds for 192 bit ecc signature generation") # put these 2 lines after code you want to time

    # ECC Digital Signature Verification
    # We can verify the signature.  If the signature is invalid it will
    # raise an Exception.

    before192edsv1 = time.perf_counter()

    public_key384e.verify(
        signature,
        short_plaintext,
        ec.ECDSA(hashes.SHA256())
    )

    after192edsv1 = time.perf_counter()
    print(f"{after192edsv1 - before192edsv1:0.4f} seconds seconds for 192 bit ecc signature verification") # put these 2 lines after

    # ECC Section ( 256 bits)
    # ECC Keypair Generation

    before256ekg = time.perf_counter()

    # private-key
    private_key256e = ec.generate_private_key(
    ec.SECP256R1()
    )

    # public-key.
    public_key256e = private_key256e.public_key()

    after256ekg = time.perf_counter()
    print(f"{after256ekg - before256ekg:0.4f} seconds for 256 bit ecc keypair generation") # put these 2 lines after code you want to time

# ECC Digital Signing
# We can sign the message using "hash-then-sign".

before256eds = time.perf_counter()

signature = private_key256e.sign(
    short_plaintext,
    ec.ECDSA(hashes.SHA256())
)

after256eds = time.perf_counter()
print(f"{after256eds - before256eds:0.4f} seconds for 256 bit ecc signature generation") # put these 2 lines after code you want to time

# ECC Digital Signature Verification
# We can verify the signature.  If the signature is invalid it will
# raise an Exception.

before256edsv1 = time.perf_counter()

public_key256e.verify(
    signature,
    short_plaintext,
    ec.ECDSA(hashes.SHA256())
)

after256edsv1 = time.perf_counter()
print(f"{after256edsv1 - before256edsv1:0.4f} seconds for 256 bit ecc signature verification") # put these 2 lines after code you want to time

# Print loop status
print(f"Completed loop {i + 1} of {num_repeats}")
