import sys
import os

if len(sys.argv) < 2:
    print("Usage: python patch_binary.py <file>")
    sys.exit(1)

filepath = sys.argv[1]
# The specific path found in the binary from the Snap SDK
old_path = b"/snap/core20/current/lib64/ld-linux-x86-64.so.2"
# The standard Linux path
new_path = b"/lib64/ld-linux-x86-64.so.2"

if not os.path.exists(filepath):
    print(f"File not found: {filepath}")
    sys.exit(1)

with open(filepath, "rb") as f:
    data = f.read()

if old_path in data:
    print(f"Found Snap interpreter path in {filepath}. Patching...")
    # Pad new_path with nulls to match old_path length strictly so we don't shift offsets
    pad_len = len(old_path) - len(new_path)
    if pad_len < 0:
        print("Error: New path is longer than old path! Cannot patch in-place.")
        sys.exit(1)
        
    replacement = new_path + (b'\x00' * pad_len)
    new_data = data.replace(old_path, replacement)
    
    with open(filepath, "wb") as f:
        f.write(new_data)
    print("Patch successful.")
else:
    print(f"Snap interpreter path not found in {filepath}. It might be already correct or using a different path.")
