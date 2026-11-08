# 4. Path Traversal

**OWASP Top 10 2021:** A01 Broken Access Control · **CWE-22**

## O problema

A rota `/files?name=...` serve documentos de uma pasta pública. O nome do arquivo vem do usuário e é anexado ao caminho sem conferência:

```python
# vulnerable.py
path = base / name
```

Se `name` contiver `../`, o caminho sobe de pasta e sai do diretório permitido.

## Explorando (em `/vuln/`)

```
/vuln/files?name=../secret.txt
```

Devolve o `secret.txt`, que fica na pasta acima da pasta pública (o conteúdo é fictício). Em um servidor real o alvo seria `../../../etc/passwd`, um `.env` ou uma chave privada.

## Corrigindo (em `fixed.py`)

```python
base = Path(FILES_DIR).resolve()
target = (base / name).resolve()
if base not in target.parents or target.suffix not in {".txt"} or not target.is_file():
    abort(404)
```

O ponto central é **resolver o caminho final antes de comparar** (`resolve()` elimina `..` e links simbólicos) e só então verificar se continua dentro da pasta permitida. Conferir a string em busca de `../` não funciona: `..%2f`, `....//` e caminhos absolutos furam filtros desse tipo.

Camadas extras:

- **Lista de extensões** (`.txt`): mesmo que algo escape, não serve qualquer tipo de arquivo.
- **404 para tudo** que falhar, sem diferenciar "não existe" de "não pode".

O teste da correção tenta vários disfarces: `../secret.txt`, `../../app/secret.txt`, `/etc/passwd`, `..%2fsecret.txt` e `bem-vindo.txt/../../secret.txt`.

## O que aprendi

A melhor correção é não aceitar caminho do usuário. Se possível, a rota receberia um id (`/files/42`) e o servidor mapearia para o arquivo. Aqui mantive o nome para mostrar a técnica de contenção, que serve quando não dá para evitar o caminho.

## Testes

`test_path_traversal_*`, `test_arquivo_publico_legitimo_*` e `test_corrigida_so_serve_extensoes_permitidas`.
