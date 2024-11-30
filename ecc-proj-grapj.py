import matplotlib.pyplot as plt

# Data
key_sizes = [80, 112, 128, 192, 256]
ecc_keypair = [0.0004, 0.0006, 0.0003, 0.0016, 0.0002]
ecc_signature_gen = [0.00052, 0.0009, 0.0002, 0.0012, 0.0004]
ecc_signature_ver = [0.0004, 0.0008, 0.0002, 0.0014, 0.0004]

# Graphs
fig, ax = plt.subplots(1, 1, figsize=(14, 10))

# ECC
ax.plot(key_sizes, ecc_keypair, marker='o', label='Keypair Generation')
ax.plot(key_sizes, ecc_signature_gen, marker='o', label='Signature Generation')
ax.plot(key_sizes, ecc_signature_ver, marker='o', label='Signature Verification')
ax.set_title('ECC Performance')
ax.set_xticks(key_sizes)
ax.set_xlabel('Key Sizes (bits)')
ax.set_ylabel('Time (seconds)')
ax.legend()

# Layout adjustment
plt.tight_layout()
plt.show()