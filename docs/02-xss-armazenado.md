# 2. Cross-Site Scripting (XSS) armazenado

**OWASP Top 10 2021:** A03 Injection · **CWE-79**

## O problema

O mural de recados grava o texto como veio e o imprime sem escapar. O template da versão vulnerável usa o filtro `|safe`, que desliga a proteção do Jinja:

```jinja
{{ c.body|safe }}
```

Quem visitar a página executa o JavaScript que outra pessoa deixou lá. Diferente do XSS refletido, aqui o atacante não precisa convencer ninguém a clicar em nada: basta publicar o recado e esperar.

## Explorando (em `/vuln/guestbook`)

Publique como recado:

```html
<script>alert('xss')</script>
```

A cada visita ao mural o navegador executa o script. Em um sistema real, em vez de `alert`, o script leria o cookie de sessão (se não for `HttpOnly`), enviaria formulários em nome da vítima ou trocaria o conteúdo da página.

## Corrigindo (em `fixed.py` e no template)

Na versão corrigida o template usa a impressão normal, que converte `<` em `&lt;`, `>` em `&gt;` e assim por diante:

```jinja
{{ c.body }}
```

O navegador mostra o texto `<script>...` na tela em vez de executá-lo. O teste confere os dois lados: o recado sai escapado (`&lt;script&gt;`) e o `<script>` cru não aparece no HTML.

## O que aprendi

- A correção está na **saída**, no momento de mostrar. Filtrar `<script>` na entrada é frágil (`<img src=x onerror=...>` passa batido).
- Template engines modernos escapam por padrão. O XSS aparece quando alguém desliga isso (`|safe`, `innerHTML`, `dangerouslySetInnerHTML`) por conveniência. Em revisão de código, essas palavras merecem atenção.
- Defesa em profundidade: um `Content-Security-Policy` restritivo e cookies `HttpOnly` reduzem o estrago se algum escape falhar. Não estão neste laboratório para manter o foco em uma falha por vez.

## Testes

`test_xss_armazenado_*` e `test_xss_no_nome_do_autor_*` (o campo autor é escapado nos dois modos, mostrando que o problema era só no `|safe`).
