# generate SHA-256 hash at upload; verify download
import hashlib

file_hashes = {} #filename: hash

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

#at upload
file_hashes[filename] = compute_hash(file_data)

#at download
expected = file_hashes[filename]
actual= compute_hash(decrypted)
if expected != actual:
    return "File corrupted", 500