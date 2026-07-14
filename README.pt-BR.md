<p align="center">
  <img src="assets/logo.svg" alt="scan_node — Scanner Defensivo de SQL Injection" width="100%" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licença-MIT-blue.svg" alt="Licença: MIT" /></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18.x-green.svg" alt="Node.js 18+" />
  <img src="https://img.shields.io/badge/dependências-zero-brightgreen.svg" alt="Zero Dependências" />
  <img src="https://img.shields.io/badge/OWASP-WSTG-alinhado-orange.svg" alt="OWASP WSTG" />
</p>

<p align="center">
  <strong>scan_node</strong> é um scanner defensivo de SQL injection sem dependências externas, construído para Node.js. Ele navega por uma aplicação web alvo, descobre vetores de entrada e avalia respostas em busca de sinais de vulnerabilidades SQLi — tudo dentro dos limites de testes de segurança autorizados.
</p>

---

## Índice

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
  - [Uso Básico](#uso-básico)
  - [Modo Seguro (Padrão)](#modo-seguro-padrão)
  - [Teste Ativo de SQLi](#teste-ativo-de-sqli)
  - [Payloads Estendidos](#payloads-estendidos)
  - [Autenticação e Cabeçalhos Personalizados](#autenticação-e-cabeçalhos-personalizados)
  - [Referência da Linha de Comandos](#referência-da-linha-de-comandos)
- [Formato de Saída](#formato-de-saída)
- [Metodologia de Detecção](#metodologia-de-detecção)
- [Mapeamento OWASP Top 10:2025](#mapeamento-owasp-top-102025)
- [Legalidade e Uso Autorizado](#legalidade-e-uso-autorizado)
- [Isenção de Responsabilidade e Limitações](#isenção-de-responsabilidade-e-limitações)
- [Contribuindo](#contribuindo)
- [Licença](#licença)

---

## Visão Geral

**scan_node** é uma ferramenta de segurança de linha de comando escrita em JavaScript puro (ES Modules) que roda sobre o Node.js. Foi desenvolvida para testadores de penetração, pesquisadores de segurança e desenvolvedores de aplicações que necessitam de um instrumento leve e auditável para identificar falhas de SQL injection em aplicações web que possuem ou estão autorizados a testar.

O scanner funciona em duas fases distintas:

1. **Crawling** — A partir de uma URL fornecida, ele navega até *N* páginas (configurável), extraindo parâmetros de consulta de URLs e campos de formulário HTML.
2. **Teste Ativo** — Para cada vetor de entrada descoberto, ele envia requisições HTTP de base e com payloads, e avalia as respostas utilizando análise heurística (correspondência de assinaturas de erro, análise diferencial booleana e comparação de códigos de status HTTP).

A versão estável atual é a **v3.0** (`scanner_v3.js`), que introduz modo seguro, verificações passivas de cabeçalhos de segurança, conjunto estendido de payloads e findings categorizados pelo OWASP.

## Funcionalidades

| Funcionalidade | Descrição |
|----------------|-----------|
| **Zero Dependências** | Utiliza exclusivamente módulos embutidos do Node.js; não é necessário `npm install`. |
| **Modo Seguro por Padrão** | Payloads ativos de SQLi estão desabilitados a menos que solicitados explicitamente (`--safe=false`). |
| **Verificações Passivas de Segurança** | Avalia cabeçalhos HTTP de segurança (HSTS, CSP, X-Content-Type-Options) e atributos de cookies. |
| **Payloads Estendidos** | Probes opcionais de SQLi baseados em UNION e temporais (`--extended-payloads=true`). |
| **Análise Diferencial Booleana** | Compara respostas para payloads booleanos `true`/`false` para detectar SQLi cego. |
| **Detecção Multi-DBMS** | Reconhece assinaturas de erro de MySQL, PostgreSQL, SQLite, MSSQL e Oracle. |
| **Tagging OWASP Top 10:2025** | Cada finding é classificado sob a categoria OWASP correspondente. |
| **Relatório em JSON** | Saída estruturada e legível por máquina, adequada para integração em pipelines CI/CD. |
| **Autenticação Personalizada** | Suporta cookies e cabeçalhos HTTP arbitrários para escaneamento autenticado. |

## Pré-requisitos

- **Node.js** ≥ 18.x (necessário para `fetch()` nativo e `AbortSignal.timeout()`)
- Acesso de rede à aplicação alvo
- **Autorização escrita** para testar o alvo (veja [Legalidade e Uso Autorizado](#legalidade-e-uso-autorizado))

## Instalação

Não é necessário um passo de instalação. Clone ou baixe o repositório e execute o scanner diretamente:

```bash
git clone https://github.com/user/scan_node.git
cd scan_node
node scanner_v3.js --help
```

## Uso

### Uso Básico

```bash
node scanner_v3.js <url-do-alvo>
```

Isso inicia a navegação pela URL do alvo (até 20 páginas por padrão), restrita à mesma origem, em **modo seguro** (apenas verificações passivas; nenhum payload ativo de SQLi é enviado).

### Modo Seguro (Padrão)

O modo seguro é o modo de operação padrão. Neste modo, o scanner realiza apenas avaliações passivas:

- Navega pela aplicação alvo e enumera vetores de entrada.
- Avalia cabeçalhos de resposta HTTP em busca de configurações incorretas de segurança.
- Inspeciona atributos de `Set-Cookie` em busca de flags `HttpOnly`, `Secure` e `SameSite` ausentes.
- Detecta formulários que utilizam o método `GET` (informativo).

```bash
node scanner_v3.js https://exemplo.com
```

### Teste Ativo de SQLi

Para habilitar o teste ativo de SQL injection, defina `--safe=false`:

```bash
node scanner_v3.js https://exemplo.com --safe=false
```

Isso instrui o scanner a enviar payloads específicos de SQLi (aspas simples, ponto e vírgula, probes booleanos true/false) contra cada vetor de entrada descoberto.

### Payloads Estendidos

Para um teste abrangente, habilite payloads estendidos junto com o modo ativo:

```bash
node scanner_v3.js https://exemplo.com --safe=false --extended-payloads=true
```

Payloads estendidos incluem:

- **Baseado em UNION**: `' UNION SELECT NULL--`
- **Baseado em tempo**: `' OR SLEEP(3)--`
- **Fechamento de comentário**: `')--`

### Autenticação e Cabeçalhos Personalizados

Para escanear páginas autenticadas, forneça cookies e/ou cabeçalhos personalizados:

```bash
# Autenticação baseada em cookie
node scanner_v3.js https://exemplo.com --cookie="sessao=abc123"

# Cabeçalhos personalizados (pode ser repetido)
node scanner_v3.js https://exemplo.com --header="Authorization: Bearer token123" --header="X-Custom: valor"
```

### Referência da Linha de Comandos

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--max-pages=N` | `20` | Número máximo de páginas a navegar. |
| `--timeout=N` | `8000` | Timeout de requisição HTTP em milissegundos. |
| `--delay=N` | `250` | Atraso entre requisições consecutivas em milissegundos. |
| `--same-origin=true\|false` | `true` | Restringir a navegação à mesma origem da URL alvo. |
| `--out=ARQUIVO` | `report.json` | Caminho do arquivo de relatório de saída. |
| `--cookie=VALOR` | — | Valor do cabeçalho Cookie a incluir nas requisições. |
| `--header="K: V"` | — | Cabeçalho HTTP personalizado (pode ser repetido). |
| `--safe=true\|false` | `true` | Quando `false`, habilita o teste ativo com payloads SQLi. |
| `--extended-payloads=true\|false` | `false` | Inclui payloads baseados em UNION e tempo (requer `--safe=false`). |
| `--allow-http-fallback=true\|false` | `false` | Fallback para HTTP se a conexão HTTPS falhar. |
| `--user-agent=STRING` | `scan-node/3.0` | Valor personalizado do cabeçalho `User-Agent`. |
| `--concurrency=N` | `1` | Número de requisições concorrentes (experimental). |

## Formato de Saída

O scanner gera um relatório JSON estruturado. O arquivo de saída padrão é `report.json`.

```jsonc
{
  "target": "https://exemplo.com",
  "started_at": "2025-07-14T10:30:00.000Z",
  "scanner": "scan-node/3.0",
  "pages_crawled": 12,
  "pages_scanned": 8,
  "findings": [
    {
      "type": "SQLi-Boolean",
      "confidence": "high",
      "url": "https://exemplo.com/busca?q=",
      "param": "q",
      "evidence": "Padrão de erro SQL encontrado: mysql.*server version",
      "owasp": "A05:2025-Injection"
    }
  ],
  "passive_findings": [
    {
      "type": "Missing-HSTS",
      "url": "https://exemplo.com/",
      "severity": "medium",
      "description": "O cabeçalho Strict-Transport-Security está ausente.",
      "owasp": "A02:2025-Security-Misconfiguration"
    }
  ],
  "interesting_headers": [
    { "url": "https://exemplo.com/", "server": "nginx/1.18.0" }
  ]
}
```

## Metodologia de Detecção

### Detecção de SQL Injection

O scanner utiliza as seguintes técnicas heurísticas:

1. **Detecção Baseada em Erro** — Correlaciona o conteúdo do corpo da resposta com 15 padrões conhecidos de assinatura de erro SQL (MySQL, PostgreSQL, SQLite, MSSQL, Oracle).
2. **Análise Diferencial Booleana** — Envia payloads booleanos pareados `true`/`false` e compara as respostas utilizando pontuação de similaridade em nível de caractere. Uma similaridade abaixo de 0.90 entre respostas pareadas indica um SQLi provável.
3. **Análise de Código de Status HTTP** — Detecta alterações inesperadas no código de status entre respostas de base e de payload.
4. **Delta do Corpo da Resposta** — Sinaliza diferenças significativas no tamanho do corpo (>15% ou >120 caracteres) entre respostas de base e de payload.

### Verificações Passivas de Segurança

O scanner v3 também avalia:

- Presença de **Strict-Transport-Security** em endpoints HTTPS.
- Presença do cabeçalho **Content-Security-Policy**.
- Presença do cabeçalho **X-Content-Type-Options**.
- Atributos de **Set-Cookie** (`HttpOnly`, `Secure`, `SameSite`).
- **Método de formulário** (GET vs POST, informativo).

## Mapeamento OWASP Top 10:2025

| Categoria de Finding | Classificação OWASP |
|---------------------|---------------------|
| SQL Injection (Boolean, Error, UNION, Time-based) | [A05:2025 — Injection](https://owasp.org/Top10/A05_2021-Injection/) |
| Cabeçalhos de Segurança Ausentes | [A02:2025 — Security Misconfiguration](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| Atributos Inseguros de Cookie | [A07:2025 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |

## Legalidade e Uso Autorizado

### Uso Permitido

Esta ferramenta foi projetada e destina-se **exclusivamente** a:

- **Testes de penetração autorizados** em aplicações que você possui ou tem permissão escrita para testar.
- **Pesquisa de segurança** conduzida dentro de limites legais e éticos.
- **Fins educacionais** em ambientes laboratoriais controlados.
- **Programas de bug bounty** onde o alvo esteja dentro do escopo definido.

### Uso Proibido

É **estritamente proibido** o uso do **scan_node** para:

- Verificar, sondar ou testar qualquer sistema sem **autorização escrita explícita** do proprietário do sistema.
- Qualquer atividade que viole leis ou regulamentos locais, nacionais ou internacionais aplicáveis.
- Acesso não autorizado ou interferência em sistemas de computador, redes ou dados.
- Qualquer forma de atividade maliciosa, disruptiva ou antiética.

### Responsabilidade Legal

O usuário assume **responsabilidade legal integral** por todas as ações realizadas com esta ferramenta. Os autores e contribuidores do **scan_node** não se responsabilizam por uso indevido, danos ou consequências legais decorrentes do uso deste software. É exclusiva obrigação do usuário garantir que todas as atividades de teste estejam em conformidade com a legislação aplicável, incluindo, mas não se limitando a:

- **Lei nº 12.965/2014 (Marco Civil da Internet)** (Brasil)
- **Lei nº 13.709/2018 (Lei Geral de Proteção de Dados — LGPD)** (Brasil)
- **Lei nº 9.609/1998 (Lei de Software)** (Brasil)
- **Computer Misuse Act 1990** (Reino Unido)
- **Computer Fraud and Abuse Act** (Estados Unidos)
- **General Data Protection Regulation (GDPR)** (União Europeia)
- Qualquer outra legislação aplicável de crimes informáticos ou proteção de dados na jurisdição do usuário

## Isenção de Responsabilidade e Limitações

> **IMPORTANTE:** Este software é fornecido "como está", sem garantia de qualquer espécie, expressa ou implícita. Consulte o arquivo [LICENCA](LICENCA) para detalhes completos.

- **scan_node** **não** substitui uma auditoria de segurança profissional ou um scanner de vulnerabilidades abrangente.
- Ele detecta um subconjunto de vetores de SQL injection; **não** garante a descoberta de todas as vulnerabilidades SQLi.
- Falsos positivos podem ocorrer. Todos os findings devem ser verificados manualmente por um profissional de segurança qualificado.
- A ferramenta pode causar efeitos colaterais na aplicação alvo (ex.: entradas em log de erros, rate limiting, modificação de dados via payloads `INSERT`/`UPDATE`). Os usuários devem exercer cautela e utilizar ambientes de teste quando possível.
- Payloads estendidos (particularmente `SLEEP()`) podem degradar o desempenho da aplicação alvo. Utilize com discrição.

## Contribuindo

Contribuições são bem-vindas. Por favor, garanta que todas as contribuições:

1. Mantenham a filosofia de zero dependências.
2. Incluam casos de teste apropriados.
3. Sigam o estilo de código existente (ES Modules, sem transpilação).
4. Sejam acompanhadas de documentação clara da alteração.

## Licença

Este projeto está licenciado sob a **Licença MIT** — a licença de código aberto permissiva mais amplamente reconhecida. Você pode usar, modificar e distribuir livremente este software para qualquer finalidade, incluindo uso comercial, desde que o aviso de copyright original e o aviso de licença sejam incluídos.

Consulte o arquivo [LICENCA](LICENCA) para o texto completo, ou visite [opensource.org/licenses/MIT](https://opensource.org/licenses/MIT).

---

<p align="center">
  <sub>Desenvolvido para fins de segurança defensiva. Utilize de forma responsável e legal.</sub>
</p>
