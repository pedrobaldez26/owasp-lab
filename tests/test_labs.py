"""Cada laboratório é testado nos dois modos: o exploit funciona em /vuln e falha em /fixed,
e o uso normal continua funcionando em /fixed (a correção não pode quebrar o app)."""
import hashlib

import pytest
from werkzeug.security import check_password_hash

from conftest import login

BOTH = ["vuln", "fixed"]


# ---------------------------------------------------------------- uso normal
@pytest.mark.parametrize("mode", BOTH)
def test_login_legitimo_funciona_nos_dois(client, mode):
    assert login(client, mode, "alice", "alice123").status_code == 302
    assert "alice" in client.get(f"/{mode}/").get_data(as_text=True)


@pytest.mark.parametrize("mode", BOTH)
def test_senha_errada_e_recusada_nos_dois(client, mode):
    assert login(client, mode, "alice", "errada").status_code == 401


@pytest.mark.parametrize("mode", BOTH)
def test_busca_legitima_funciona_nos_dois(client, mode):
    html = client.get(f"/{mode}/search?q=mouse").get_data(as_text=True)
    assert "Mouse sem fio" in html and "Teclado" not in html


# ---------------------------------------------------------------- 1. SQL injection
def test_sqli_login_bypass_funciona_na_vulneravel(client):
    # o comentário SQL (--) descarta a checagem de senha
    r = login(client, "vuln", "admin' --", "qualquer-coisa")
    assert r.status_code == 302
    assert "admin" in client.get("/vuln/").get_data(as_text=True)


def test_sqli_login_bypass_falha_na_corrigida(client):
    for payload in ["admin' --", "' OR '1'='1' --", "admin'/*"]:
        assert login(client, "fixed", payload, "x").status_code == 401, payload
    assert "Logado como" not in client.get("/fixed/").get_data(as_text=True)


def test_sqli_union_extrai_dados_de_outra_tabela(client):
    payload = "zzz' UNION SELECT name, value, 0 FROM secrets --"
    assert "FLAG{dados-fake-do-laboratorio}" in client.get("/vuln/search", query_string={"q": payload}).get_data(as_text=True)
    assert "FLAG{" not in client.get("/fixed/search", query_string={"q": payload}).get_data(as_text=True)


def test_sqli_erro_de_banco_vaza_na_vulneravel_e_nao_na_corrigida(client):
    html = login(client, "vuln", "'", "x").get_data(as_text=True)
    assert "Erro de banco" in html and "SELECT id FROM users" in html

    html = login(client, "fixed", "'", "x").get_data(as_text=True)
    assert "SELECT" not in html and "Erro de banco" not in html


def test_busca_corrigida_trata_curinga_como_texto(client):
    assert "Nada encontrado" in client.get("/fixed/search?q=%25%25%25").get_data(as_text=True)


# ---------------------------------------------------------------- 2. XSS armazenado
XSS = "<script>alert('xss')</script>"


def test_xss_armazenado_executa_na_vulneravel(client):
    client.post("/vuln/guestbook", data={"author": "atacante", "body": XSS})
    assert XSS in client.get("/vuln/guestbook").get_data(as_text=True)


def test_xss_armazenado_e_escapado_na_corrigida(client):
    client.post("/fixed/guestbook", data={"author": "atacante", "body": XSS})
    html = client.get("/fixed/guestbook").get_data(as_text=True)
    assert XSS not in html
    assert "&lt;script&gt;" in html


def test_xss_no_nome_do_autor_e_escapado_nos_dois(client):
    for mode in BOTH:
        client.post(f"/{mode}/guestbook", data={"author": "<img src=x onerror=alert(1)>", "body": "oi"})
        assert "<img src=x" not in client.get(f"/{mode}/guestbook").get_data(as_text=True), mode


# ---------------------------------------------------------------- 3. IDOR
def test_idor_le_nota_de_outro_usuario_na_vulneravel(client):
    login(client, "vuln", "alice", "alice123")
    r = client.get("/vuln/invoices/3")  # nota 3 é do bob
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "bob" in html and "cartão final 0000" in html


def test_idor_bloqueado_na_corrigida_mas_a_propria_nota_abre(client):
    login(client, "fixed", "alice", "alice123")
    assert client.get("/fixed/invoices/3").status_code == 404
    assert client.get("/fixed/invoices/4").status_code == 404
    assert client.get("/fixed/invoices/1").status_code == 200


@pytest.mark.parametrize("mode", BOTH)
def test_nota_exige_login_nos_dois(client, mode):
    r = client.get(f"/{mode}/invoices/1")
    assert r.status_code == 302 and "login" in r.headers["Location"]


# ---------------------------------------------------------------- 4. Path traversal
def test_path_traversal_le_arquivo_fora_da_pasta_na_vulneravel(client):
    r = client.get("/vuln/files", query_string={"name": "../secret.txt"})
    assert r.status_code == 200 and "FAKE-INTERNAL-TOKEN" in r.get_data(as_text=True)


def test_path_traversal_bloqueado_na_corrigida(client):
    for name in ["../secret.txt", "../../app/secret.txt", "/etc/passwd", "..%2fsecret.txt", "bem-vindo.txt/../../secret.txt"]:
        r = client.get("/fixed/files", query_string={"name": name})
        assert r.status_code == 404, name
        assert "FAKE-INTERNAL-TOKEN" not in r.get_data(as_text=True)


@pytest.mark.parametrize("mode", BOTH)
def test_arquivo_publico_legitimo_abre_nos_dois(client, mode):
    r = client.get(f"/{mode}/files", query_string={"name": "politica.txt"})
    assert r.status_code == 200 and "Política de uso" in r.get_data(as_text=True)


def test_corrigida_so_serve_extensoes_permitidas(client, app, tmp_path):
    (tmp_path / "dados.json").write_text("{}")
    app.config["FILES_DIR"] = str(tmp_path)
    assert client.get("/fixed/files", query_string={"name": "dados.json"}).status_code == 404


# ---------------------------------------------------------------- 5. Hash fraco
WORDLIST = ["123456", "password", "admin2024", "alice123", "bob-password", "qwerty"]


def dump_hashes(app, mode):
    rows = app.extensions["dbs"][mode].execute("SELECT username, password_hash FROM users").fetchall()
    return {r["username"]: r["password_hash"] for r in rows}


def test_md5_vazado_e_quebrado_com_wordlist_pequena(app):
    cracked = {}
    for user, digest in dump_hashes(app, "vuln").items():
        for word in WORDLIST:
            if hashlib.md5(word.encode()).hexdigest() == digest:
                cracked[user] = word
    assert cracked == {"admin": "admin2024", "alice": "alice123", "bob": "bob-password"}


def test_hash_forte_nao_cai_para_md5_e_tem_sal(app):
    hashes = dump_hashes(app, "fixed")
    for user, stored in hashes.items():
        assert not any(hashlib.md5(w.encode()).hexdigest() == stored for w in WORDLIST)
        assert stored.startswith(("scrypt:", "pbkdf2:"))
    assert check_password_hash(hashes["alice"], "alice123")


def test_mesma_senha_gera_hashes_diferentes_na_corrigida():
    from app.seed import md5_hex, strong_hash

    assert md5_hex("igual") == md5_hex("igual")  # sem sal: mesma senha, mesmo hash
    assert strong_hash("igual", "pbkdf2:sha256:1000") != strong_hash("igual", "pbkdf2:sha256:1000")  # com sal: cada hash é único


# ---------------------------------------------------------------- guarda de localhost
def test_so_responde_para_localhost(client):
    assert client.get("/vuln/", headers={"Host": "localhost:5001"}).status_code == 200
    assert client.get("/vuln/", headers={"Host": "127.0.0.1:5001"}).status_code == 200
    for host in ["192.168.0.10:5001", "lab.example.com", "evil.localhost.example"]:
        assert client.get("/vuln/", headers={"Host": host}).status_code == 403, host
