import os

from argon2.low_level import Type, hash_secret_raw

def new_salt() -> bytes:
    return os.urandom(16)

def derive_key(password = str, salt : bytes) -> bytes:
    return hash_secret_raw(secret=password.encode("utf-8"), salt=salt, time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=32, type=Type.ID)
