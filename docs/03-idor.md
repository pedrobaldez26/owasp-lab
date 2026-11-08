# 3. IDOR (referência direta e insegura a objeto)

**OWASP Top 10 2021:** A01 Broken Access Control · **CWE-639**

## O problema

As notas fiscais abrem por `/invoices/<id>`. A rota confere se você está logado, mas **não** se a nota é sua:

```python
# vulnerable.py
row = db().execute("... FROM invoices i ... WHERE i.id = ?", (invoice_id,)).fetchone()
```

A consulta é parametrizada (não há SQL injection aqui, de propósito) e mesmo assim a rota é insegura. Autenticação responde "quem é você"; faltou a autorização, "isso é seu?".

## Explorando (em `/vuln/`)

Entre como `alice` / `alice123` e abra a nota **3**, que pertence ao `bob`:

```
/vuln/invoices/3
```

A página mostra a nota dele, com a observação "cartão final 0000". Como os ids são sequenciais, um script percorre 1, 2, 3... e baixa as notas de todo mundo. Esse tipo de falha é uma das mais comuns em API, e ferramenta automática não acha: o código "funciona".

## Corrigindo (em `fixed.py`)

A própria consulta passa a exigir que a nota seja do usuário logado:

```python
"... WHERE i.id = ? AND i.owner_id = ?", (invoice_id, user["id"])
```

Duas escolhas:

- **Filtrar na consulta**, e não buscar e depois comparar. Fica difícil esquecer a checagem em um caminho novo, porque o dado alheio nem chega a ser carregado.
- **Responder 404, não 403.** Um 403 confirmaria que a nota existe; com 404 quem não é dono não consegue nem enumerar quais ids são válidos.

## O que aprendi

Trocar o id sequencial por UUID dificulta adivinhar, mas **não corrige**: se o link vazar, o acesso continua aberto. O que corrige é a checagem de dono no servidor. UUID é uma camada a mais, não a defesa.

## Testes

`test_idor_le_nota_de_outro_usuario_na_vulneravel` e `test_idor_bloqueado_na_corrigida_mas_a_propria_nota_abre` (a correção não pode impedir o dono de ver a própria nota).
