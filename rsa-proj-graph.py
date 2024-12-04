import matplotlib.pyplot as plt
import numpy as np

# Data
key_sizes = [80, 112, 128, 192, 256]
rsa_keypair = [0.0131, 0.0376, 0.1697, 5.0767, 27.9291]
rsa_encryption = [0.0001, 0.0001, 0.0003, 0.0004, 0.0019]
rsa_decryption = [0.0006, 0.0011, 0.017, 0.0491, 0.2183]
rsa_signature_gen = [0.0004, 0.0005, 0.0008, 0.0450, 0.1908]
rsa_signature_ver = [0.002, 0.0005, 0.00011, 0.00010, 0.0011]

# Graphs
fig, ax = plt.subplots(1, 1, figsize=(14, 10))

ax.plot(key_sizes, rsa_keypair, marker='o', label='Keypair Generation')
ax.plot(key_sizes, rsa_decryption, marker='o', label='Decryption')
ax.plot(key_sizes, rsa_signature_gen, marker='o', label='Signature Generation')
ax.plot(key_sizes, rsa_signature_ver, marker='o', label='Signature Verification')
ax.set_title('RSA Performance')
ax.set_xticks(key_sizes)
ax.set_xlabel('Key Sizes (bits)')
ax.set_ylabel('Time (seconds)')
ax.legend()

# Layout adjustment
plt.tight_layout()
plt.show()