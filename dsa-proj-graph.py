import matplotlib.pyplot as plt

# Data
key_sizes = [80, 112, 128, 192, 256]
dsa_keypair = [0.05, 0.16, 2, 3.66, 4]
dsa_signature_gen = [0.0005, 0.0005, 0.0012, 0.0014, 0.0015]
dsa_signature_ver = [0.0006, 0.0007, 0.0013, 0.0015, 0.0016]

# Graphs
fig, ax = plt.subplots(1, 1, figsize=(14, 10))

# DSA
ax.plot(key_sizes, dsa_keypair, marker='o', label='Keypair Generation')
ax.plot(key_sizes, dsa_signature_gen, marker='o', label='Signature Generation')
ax.plot(key_sizes, dsa_signature_ver, marker='o', label='Signature Verification')
ax.set_title('DSA Performance')
ax.set_xticks(key_sizes)
ax.set_xlabel('Key Sizes (bits)')
ax.set_ylabel('Time (seconds)')
ax.legend()

# Layout adjustment
plt.tight_layout()
plt.show()