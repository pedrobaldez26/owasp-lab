"""Banco em memória com dados FICTÍCIOS. Um por modo, para um não contaminar o outro."""
import hashlib
import sqlite3

from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, price_cents INTEGER NOT NULL);
CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT NOT NULL, value TEXT NOT NULL);
CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), description TEXT NOT NULL, amount_cents INTEGER NOT NULL);
CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT NOT NULL, body TEXT NOT NULL);
"""

# Senhas fracas de propósito: o laboratório de hash fraco precisa delas.
USERS = [("admin", "admin2024", "admin"), ("alice", "alice123", "user"), ("bob", "bob-password", "user")]

PRODUCTS = [
    ("Teclado mecânico", "Switch azul, ABNT2", 24990),
    ("Mouse sem fio", "Bateria de 12 meses", 7990),
    ("Monitor 24 pol", "Full HD, 75 Hz", 69900),
    ("Webcam HD", "720p com microfone", 12900),
]

INVOICES = [  # (dono, descrição, valor)
    ("alice", "Teclado mecânico", 24990),
    ("alice", "Mouse sem fio", 7990),
    ("bob", "Monitor 24 pol (cartão final 0000)", 69900),
    ("admin", "Licenças internas", 150000),
]


def md5_hex(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324 - inseguro de propósito (modo vulnerável)


def strong_hash(password: str, method=None) -> str:
    # scrypt quando existe; PBKDF2 em Pythons sem hashlib.scrypt (ex.: o da Apple).
    # `method` existe para os testes usarem poucas iterações e não esperarem segundos por app criado.
    method = method or ("scrypt" if hasattr(hashlib, "scrypt") else "pbkdf2:sha256")
    return generate_password_hash(password, method=method)


def build_db(mode: str, hash_method=None) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)

    hasher = md5_hex if mode == "vuln" else (lambda pw: strong_hash(pw, hash_method))
    for username, password, role in USERS:
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, hasher(password), role))
    conn.executemany("INSERT INTO products (name, description, price_cents) VALUES (?, ?, ?)", PRODUCTS)
    conn.execute("INSERT INTO secrets (name, value) VALUES ('flag', 'FLAG{dados-fake-do-laboratorio}')")
    for owner, desc, cents in INVOICES:
        conn.execute(
            "INSERT INTO invoices (owner_id, description, amount_cents) SELECT id, ?, ? FROM users WHERE username = ?",
            (desc, cents, owner),
        )
    conn.execute("INSERT INTO comments (author, body) VALUES ('alice', 'Ótimo atendimento!')")
    conn.commit()
    return conn
