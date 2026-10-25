# header-audit

![testes](https://github.com/BarrinDev/header-audit/actions/workflows/testes.yml/badge.svg)

Script em Python que olha os cabeçalhos de segurança de um site (HSTS, CSP, X-Frame-Options
e afins) e o certificado TLS, dá uma nota e diz o que falta e como arrumar.

Comecei isso porque faço sites pra pequenos negócios e queria saber se estavam bem
configurados. Não estavam: rodei nos meus sites publicados e todos tiraram D. O HTTPS estava
certo, porque a Vercel já cuida disso, mas faltavam CSP, proteção contra clickjacking,
`nosniff` e `Referrer-Policy`. Vou corrigir e depois coloco aqui o antes e depois.

## Rodando

Precisa de Python 3.10 ou mais novo. Não tem dependência, é tudo da biblioteca padrão.

```bash
git clone https://github.com/BarrinDev/header-audit.git
cd header-audit
python -m header_audit seusite.com.br
```

Dá pra passar vários sites de uma vez, salvar um relatório em Markdown com
`--markdown relatorio.md` ou gerar JSON com `--json`. Se encontrar alguma falha, o script sai
com código 1, então também serve pra rodar num CI e barrar um deploy que tirou um cabeçalho.

Se preferir ter o comando instalado: `pip install .` e depois `header-audit seusite.com.br`.

## Exemplo

Rodando no `example.com`, que é um domínio reservado justamente pra exemplos:

```text
https://example.com
Nota F (14/100)

  [FALHA] Strict-Transport-Security (HSTS): Cabeçalho ausente: o navegador aceita voltar para HTTP.
          Como corrigir: Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains
  [FALHA] Content-Security-Policy (CSP): Cabeçalho ausente: nada limita de onde vêm scripts e estilos.
          Como corrigir: Comece por: Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'
  [FALHA] Proteção contra clickjacking: O site pode ser carregado dentro de um iframe de outro domínio.
  [AVISO] HTTPS: O endereço HTTP responde sem redirecionar para HTTPS.
  [AVISO] X-Content-Type-Options: O navegador pode adivinhar o tipo do arquivo (MIME sniffing).
  [AVISO] Referrer-Policy: Cabeçalho ausente; vale o padrão do navegador.
  [INFO ] Permissions-Policy: Cabeçalho ausente; câmera, microfone e localização ficam no padrão.
  [OK   ] Certificado TLS: Válido por mais 61 dias.
  [OK   ] Exposição de versões: Nenhuma versão de software nos cabeçalhos.
```

O relatório em Markdown desse mesmo teste está em [exemplos/](exemplos/relatorio-example-com.md).

## O que ele confere

- se o site usa HTTPS e se o `http://` redireciona pro `https://`
- validade do certificado (avisa quando falta menos de 30 dias)
- HSTS, e se o `max-age` é de pelo menos seis meses
- CSP, incluindo `'unsafe-inline'`, `'unsafe-eval'` e curingas no `script-src`
- `X-Frame-Options` ou `frame-ancestors`, contra clickjacking
- `X-Content-Type-Options`, `Referrer-Policy` e `Permissions-Policy`
- servidor mostrando versão (`Server: nginx/1.18.0`, `X-Powered-By: PHP/8.1`...)
- cookies sem `Secure`, `HttpOnly` ou `SameSite`

A nota é critério meu: começa em 100 e perde 20 pontos por falha, 8 por aviso e 2 por item
informativo. Serve pra comparar o mesmo site antes e depois de mexer, não pra comparar com
outras ferramentas.

## Como o código está dividido

- `fetch.py` faz um GET, segue até 5 redirecionamentos e lê só os cabeçalhos (não baixa a página)
- `checks.py` tem uma função por regra e não acessa a rede, então dá pra testar tudo com cabeçalho inventado
- `report.py` monta a saída em texto, Markdown ou JSON
- `cli.py` cuida dos argumentos

Testes:

```bash
python -m unittest discover -s tests -v
```

Eles também rodam no GitHub Actions a cada push, em Python 3.10 e 3.12.

## O que ainda não faz

- olha só a página que você passou, não o site inteiro
- não roda JavaScript, então cabeçalho colocado por script não aparece
- confere configuração, não procura vulnerabilidade. Não substitui um pentest

Ideias pra próxima versão: checar várias páginas do mesmo site, ler o `security.txt` e
comparar dois relatórios pra mostrar o que melhorou.

O script faz uma requisição normal, igual a abrir a página no navegador, mas use em site seu
ou de quem te autorizou.

Licença MIT.
