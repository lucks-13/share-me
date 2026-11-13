import os

from argon2.low_level import Type, hash_secret_raw

def new_salt() -> bytes:
    return os.urandom(16)

def derive_key() -> 