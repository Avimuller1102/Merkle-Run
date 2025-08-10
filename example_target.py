

import os
import hashlib
import random
import time

def main():
    # generate some deterministic pseudo-random bytes and write them
    r = random.Random()  # will be seeded by merklerun
    data = bytes([r.randrange(0, 256) for _ in range(1024)])
    with open("out.bin", "wb") as f:
        f.write(data)

    # read this file back and print its sha256
    size = os.path.getsize("out.bin")
    h = hashlib.sha256(open("out.bin", "rb").read()).hexdigest()
    print(f"size={size} sha256={h}")

if __name__ == "__main__":
    main()
