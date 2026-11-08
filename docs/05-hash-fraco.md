# 5. Armazenamento fraco de senhas

**OWASP Top 10 2021:** A02 Cryptographic Failures · **CWE-916** (também CWE-327)

## O problema

A versão vulnerável guarda `MD5(senha)` sem sal:

```python
hashlib.md5(password.encode()).hexdigest()
```

MD5 foi feito para ser **rápido**, e isso é exatamente o que se evita em hash de senha. Uma placa de vídeo comum testa bilhões de combinações por segundo. Sem sal, a mesma senha gera sempre o mesmo hash, então uma tabela pronta de hashes comuns quebra tudo de uma vez, e usuários com a mesma senha são identificáveis.

## Demonstrando

Suponha que o banco vazou (por exemplo, por causa do laboratório 1). O teste `test_md5_vazado_e_quebrado_com_wordlist_pequena` pega os hashes e compara com o MD5 de uma lista de seis palavras. Resultado: os três usuários são recuperados na hora, sem nenhum esforço de computação.

O teste não usa ferramenta de quebra de senha. Basta calcular o hash das palavras e comparar, o que mostra que o problema não é sofisticado.

## Corrigindo (em `seed.py` e `fixed.py`)

```python
generate_password_hash(password, method="scrypt")   # ou "pbkdf2:sha256" onde scrypt não existe
check_password_hash(stored, password)
```

- **scrypt/PBKDF2** são deliberadamente lentos e configuráveis (custo). Cada tentativa do atacante custa tempo e memória.
- **Sal aleatório por senha**: a mesma senha gera hashes diferentes (há um teste: `test_mesma_senha_gera_hashes_diferentes_na_corrigida`), então não existe tabela pronta.
- A conferência fica em `check_password_hash`, que lê parâmetros e sal do próprio valor guardado. Isso permite aumentar o custo no futuro sem quebrar contas antigas.

Nota prática: o Python da Apple vem sem `hashlib.scrypt`; o código cai para PBKDF2-SHA256 nesse caso, e o formato guardado indica qual foi usado.

## O que aprendi

- Hash de senha não é o mesmo que hash de integridade. SHA-256 também é rápido demais para guardar senha.
- Uma senha fraca (`alice123`) continua fraca com qualquer hash: a lentidão só ganha tempo. Por isso política de senha e bloqueio de tentativas importam.
- Quem vaza o banco vaza o hash, e o que o hash faz é decidir quanto tempo isso vale para o atacante.

## Testes

`test_md5_vazado_*`, `test_hash_forte_nao_cai_para_md5_e_tem_sal`, `test_mesma_senha_gera_hashes_diferentes_na_corrigida`.
