# 1. SQL Injection

**OWASP Top 10 2021:** A03 Injection · **CWE-89** (e CWE-209, vazamento de informação em mensagem de erro)

## O problema

O login e a busca montam o SQL concatenando texto digitado pelo usuário (`vulnerable.py`, funções `login` e `search`):

```python
sql = f"SELECT id FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
```

O banco não tem como saber onde termina o que o programador escreveu e começa o que o usuário digitou.

## Explorando (em `/vuln/`)

**Entrar como admin sem saber a senha.** No campo usuário:

```
admin' --
```

A consulta vira `... WHERE username = 'admin' --' AND password_hash = '...'`. O `--` comenta o resto, e a checagem de senha deixa de existir.

**Ler uma tabela que a tela não mostra.** Na busca:

```
zzz' UNION SELECT name, value, 0 FROM secrets --
```

O `UNION` anexa o conteúdo de `secrets` ao resultado da busca. A busca devolve três colunas, então o `SELECT` injetado também precisa ter três. É assim que se descobre a estrutura na prática: tentar, olhar o erro, ajustar o número de colunas.

**Erro que ajuda o atacante.** Um simples `'` no usuário faz a versão vulnerável imprimir o erro do banco *e a consulta inteira*. Isso entrega o nome das tabelas e o formato do SQL.

## Corrigindo (em `fixed.py`)

```python
db().execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
```

Consulta parametrizada: o valor viaja separado do SQL e nunca é interpretado como código. Os mesmos payloads viram texto comum e não encontram nada.

Outras mudanças na versão corrigida:

- A senha não entra mais na consulta. Busca-se o usuário e a senha é conferida em código (veja o laboratório 5).
- O erro de banco vai para o log do servidor, e o usuário recebe uma mensagem genérica.
- Na busca com `LIKE`, `%` e `_` digitados viram texto (`ESCAPE`), senão o usuário ainda controlaria o padrão.

## O que aprendi

Escapar aspas manualmente não é correção: sempre existe um caso que escapa (outra codificação, outro dialeto). A correção é separar dado de código, não "limpar" o dado.

## Testes

`test_sqli_login_bypass_*`, `test_sqli_union_*`, `test_sqli_erro_de_banco_*` em `tests/test_labs.py`.
