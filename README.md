# owasp-lab

Cinco falhas comuns de aplicação web, cada uma implementada em duas versões lado a lado: a **vulnerável** (`/vuln/...`) e a **corrigida** (`/fixed/...`). Os testes provam que o ataque funciona em uma e falha na outra, e que a correção não quebra o uso normal.

Fiz como exercício de estudo para entender cada falha por dentro: escrever o código errado, explorar e depois consertar ensina mais que ler a lista do OWASP.

> **Aviso.** Este projeto é vulnerável de propósito e usa apenas dados fictícios. Foi feito para rodar na sua máquina, para estudo. O servidor escuta só em `127.0.0.1` (não há opção para mudar) e recusa requisições cujo `Host` não seja `localhost`, para não ser exposto por engano. Não publique em servidor, e não copie o código de `vulnerable.py` para projeto nenhum.

## Os laboratórios

| # | Falha | OWASP Top 10 2021 | CWE | Roteiro |
|---|-------|-------------------|-----|---------|
| 1 | SQL Injection (login e busca) | A03 Injection | 89 | [docs/01-sql-injection.md](docs/01-sql-injection.md) |
| 2 | XSS armazenado (mural de recados) | A03 Injection | 79 | [docs/02-xss-armazenado.md](docs/02-xss-armazenado.md) |
| 3 | IDOR (notas fiscais de outros usuários) | A01 Broken Access Control | 639 | [docs/03-idor.md](docs/03-idor.md) |
| 4 | Path Traversal (download de arquivos) | A01 Broken Access Control | 22 | [docs/04-path-traversal.md](docs/04-path-traversal.md) |
| 5 | Hash de senha fraco (MD5 sem sal) | A02 Cryptographic Failures | 916 | [docs/05-hash-fraco.md](docs/05-hash-fraco.md) |

Cada roteiro tem: o que está errado, o payload para explorar, por que funciona, como foi corrigido e o que aprendi.

## Como está organizado

```
app/vulnerable.py   as rotas com as falhas, cada uma marcada com [VULN n]
app/fixed.py        as mesmas rotas, corrigidas, marcadas com [FIX n]
app/seed.py         banco em memória com dados fictícios (um por modo)
app/templates/      a única diferença visível do XSS está em guestbook.html
tests/test_labs.py  exploit x correção, nos dois modos
docs/               um roteiro por laboratório
```

Ter as duas versões na mesma aplicação, com as mesmas rotas, deixa a comparação direta: abra `vulnerable.py` e `fixed.py` lado a lado e a diferença de cada função é a própria lição. Cada modo tem seu próprio banco e sua própria chave de sessão, então um não contamina o outro.

## Rodando

Python 3.9 ou mais novo.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

python run.py
```

Abra http://localhost:5001. Usuários fictícios: `alice` / `alice123`, `bob` / `bob-password`, `admin` / `admin2024`.

Para um primeiro teste, em `/vuln/login` use `admin' --` como usuário e qualquer senha. Depois tente o mesmo em `/fixed/login`.

## Testes

```bash
pytest
```

São 27 testes. Os de exploração têm sempre os dois lados, por exemplo:

```python
def test_sqli_login_bypass_funciona_na_vulneravel(client): ...
def test_sqli_login_bypass_falha_na_corrigida(client): ...
```

Também há testes de "uso normal funciona nos dois modos" (login legítimo, busca, arquivo público, dono vendo a própria nota). Sem eles, uma "correção" que simplesmente bloqueia tudo passaria.

## O que não está coberto

- CSRF, SSRF, upload de arquivo e deserialização insegura ficaram de fora para manter cinco laboratórios enxutos.
- A versão corrigida não tem limite de tentativas de login, CSRF token nem cabeçalhos de segurança. Está "corrigida" no que cada laboratório ensina, não é um app pronto para produção. Para um exemplo com essas camadas, veja o `estoque-simples`.
- Para praticar exploração de forma mais ampla, existem projetos dedicados como OWASP Juice Shop e DVWA. Este aqui é menor de propósito: a ideia é ler todo o código.

## Licença

MIT
