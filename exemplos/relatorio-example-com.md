# Relatório de cabeçalhos de segurança

Gerado em 2026-10-24 pelo header-audit.

## https://example.com

**Nota F** (14/100)

| Situação | Item | O que foi visto | Como corrigir |
|---|---|---|---|
| FALHA | Strict-Transport-Security (HSTS) | Cabeçalho ausente: o navegador aceita voltar para HTTP. | Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains |
| FALHA | Content-Security-Policy (CSP) | Cabeçalho ausente: nada limita de onde vêm scripts e estilos. | Comece por: Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self' |
| FALHA | Proteção contra clickjacking | O site pode ser carregado dentro de um iframe de outro domínio. | Adicione X-Frame-Options: SAMEORIGIN ou a diretiva CSP frame-ancestors 'self'. |
| AVISO | HTTPS | O endereço HTTP responde sem redirecionar para HTTPS. | Configure um redirecionamento 301 de http:// para https://. |
| AVISO | X-Content-Type-Options | O navegador pode adivinhar o tipo do arquivo (MIME sniffing). | Adicione: X-Content-Type-Options: nosniff |
| AVISO | Referrer-Policy | Cabeçalho ausente; vale o padrão do navegador. | Adicione: Referrer-Policy: strict-origin-when-cross-origin |
| INFO | Permissions-Policy | Cabeçalho ausente; câmera, microfone e localização ficam no padrão. | Desligue o que o site não usa, por exemplo: Permissions-Policy: camera=(), microphone=(), geolocation=() |
| OK | Certificado TLS | Válido por mais 61 dias. |  |
| OK | Exposição de versões | Nenhuma versão de software nos cabeçalhos. |  |
