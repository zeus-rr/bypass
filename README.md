# Bypass

Ferramenta em Bash para **extração de hashes** de arquivos protegidos (PDF, ZIP, RAR e 7-Zip), integração com **John the Ripper**, geração de wordlists com **Crunch**, relatórios e **recriptografia com nova senha**.


> Use somente em **arquivos próprios** ou com **autorização explícita** para auditoria.
> Não utilize para atacar sites, logins, arquivos ou sistemas de terceiros.

---

## Aviso legal

Esta ferramenta **não** remove senha sem a chave, **não** faz bypass de criptografia e **não** ataca serviços remotos.

| Permitido | Não permitido |
|-----------|----------------|
| Recuperar senha de arquivo **seu** | Quebrar senha de arquivo de terceiros |
| Auditoria com **autorização por escrito** | Atacar sites, logins ou sistemas |
| Recriptografar **sabendo a senha atual** | “Trocar senha sem conhecer a atual” |
| Estudo de hashes em laboratório próprio | Distribuir hashes ou senhas de terceiros |

O uso indevido é de responsabilidade exclusiva de quem executa o script.

---

## O que faz

- Detecta automaticamente PDF, ZIP, RAR e 7-Zip
- Extrai hash no formato do John the Ripper (`pdf2john`, `zip2john`, `rar2john`, `7z2john`)
- Aceita arquivo **local** ou **URL http/https** (download autorizado)
- Copia o hash para a área de transferência
- Consulta MD5 / SHA1 / SHA256 em bases **públicas** (hashes simples, não PDF/ZIP)
- Executa John the Ripper com wordlist escolhida
- Gera wordlists com Crunch
- Mantém histórico CSV e relatórios TXT + HTML
- Recriptografa com **nova senha** (opção 13) — **exige a senha atual**
- Diagnóstico do ambiente (ferramentas instaladas)

### O que **não** faz

- Não descriptografa sem a senha (ou sem recuperá-la de forma autorizada)
- Não altera o arquivo original na recriptografia (gera um **arquivo novo**)
- Não quebra hashes de PDF/ZIP/RAR/7z em “bases online” — esses formatos exigem John + wordlist
- Não é um cracker de contas, sites ou redes

---

## Requisitos

Sistema: Linux (Debian/Ubuntu, Kali, Termux com adaptações). Bash 4+.

### Obrigatórios para o fluxo principal

```bash
sudo apt update
sudo apt install john curl
```

O pacote `john` costuma incluir os extratores (`zip2john`, `pdf2john`, etc.). Se não vierem no PATH, o script procura em caminhos comuns (`/usr/share/john`, `run/`, etc.).

Wordlist padrão (opcional, mas recomendada):

```bash
sudo apt install wordlists
# em Kali: /usr/share/wordlists/rockyou.txt
# se estiver gzipada:
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

### Opcionais por recurso

| Recurso | Pacote / binário |
|---------|------------------|
| Wordlists com Crunch | `crunch` |
| Recriptografar PDF | `qpdf` |
| Recriptografar ZIP / 7z (recomendado) | `p7zip-full` (`7z`) |
| Recriptografar ZIP (fallback) | `zip` + `unzip` |
| Recriptografar RAR | `rar` (CLI; `unrar` só extrai) |
| Download | `curl` ou `wget` |
| Copiar hash | `xclip`, `xsel`, `wl-copy`, `pbcopy` ou `termux-clipboard-set` |

```bash
sudo apt install crunch qpdf p7zip-full unzip zip
```

---

## Instalação

```bash
git clone https://github.com/zeus-rr/bypass.git
cd bypass
chmod +x bypass.sh
./bypass.sh
```

Ou:

```bash
bash bypass.sh
```

Ajuda e versão:

```bash
./bypass.sh --help
./bypass.sh --version
```

Dados da ferramenta ficam em `~/.bypass/` (hashes, wordlists, downloads, relatórios, histórico). **Não commite essa pasta.**

---

## Menu

| Opção | Função |
|------:|--------|
| 1 | Extrair hash (arquivo local ou URL) |
| 2 | Executar John the Ripper |
| 3 | Exibir histórico |
| 4 | Gerar relatório TXT + HTML |
| 5 | Listar hashes gerados |
| 6 | Status / diagnóstico do ambiente |
| 7 | Limpar histórico |
| 8 | Gerar wordlist com Crunch |
| 9 | Listar wordlists disponíveis |
| 10 | Extrair hash a partir de um link/URL |
| 11 | Copiar último hash |
| 12 | Consultar hash (MD5 / SHA1 / SHA256) |
| 13 | Recriptografar com nova senha (**exige senha atual**) |
| 0 | Sair |

---

## Fluxo típico (recuperação autorizada)

1. Opção **1** ou **10** — seleciona o arquivo e extrai o hash.
2. Opção **2** — escolhe uma wordlist e roda o John.
3. Se a senha for encontrada, fica disponível nesta sessão.
4. Opção **13** (opcional) — gera um **novo** arquivo com senha nova, usando a senha atual.

### Recriptografia (opção 13)

- **PDF** → `qpdf` (AES-256)
- **ZIP** → `7z` (AES-256) ou fallback `unzip` + `zip` (criptografia mais fraca)
- **7z** → `7z` com cabeçalho criptografado (`-mhe=on`)
- **RAR** → CLI `rar` (`-hp`)

Regras:

- A senha **atual é obrigatória** (pode usar a recuperada pelo John na mesma sessão).
- O original **não é modificado nem apagado**.
- Saída em `~/.extrator-pro/recriptografados/`.

---

## Diretórios

| Caminho | Conteúdo |
|---------|----------|
| `~/.bypass/hashes/` | Arquivos `.hash` extraídos |
| `~/.bypass/wordlists/` | Wordlists geradas com Crunch |
| `~/.bypass/downloads/` | Arquivos baixados por URL |
| `~/.bypass/relatorios/` | Relatórios TXT e HTML |
| `~/.bypass/recriptografados/` | Arquivos com nova senha |
| `~/.bypass/historico.csv` | Histórico de operações |

---

## Consulta de hash online (opção 12)

Serve **somente** para digestos simples:

- MD5 (32 hex)
- SHA1 (40 hex)
- SHA256 (64 hex)

Hashes no formato John (`$pdf$`, `$zip2$`, `$rar$`, `$7z$`, `$office$`) **não** são consultáveis nessas bases. Use a opção 2.

O hash pode ser enviado a um serviço externo. Confirme antes de consultar.

---

## `.gitignore` sugerido

```gitignore
.bypass/
*.hash
*.txt
!README.md
!LICENSE
downloads/
relatorios/
wordlists/
recriptografados/
historico.csv
```

Não versionar hashes, wordlists geradas nem arquivos protegidos de testes reais.

---

## Segurança

- Confirme autorização **antes** de baixar URLs ou processar arquivos.
- Não compartilhe hashes extraídos publicamente.
- Prefira wordlists geradas por você para testes controlados.
- Após o John encontrar uma senha, trate-a como segredo (o script pode copiá-la para a área de transferência).
- Recriptografia com `zip` tradicional é mais fraca que AES via `7z` / `qpdf`.

---

## Limitações conhecidas

- Sem `john` e os `*2john`, a extração não funciona.
- Sem `qpdf` / `7z` / `rar`, a opção 13 falha no formato correspondente (com mensagem clara).
- Wordlists enormes no Crunch podem esgotar disco; o script avisa estimativas grandes.
- Download limitado a 500 MB por arquivo.
- Testado como script interativo em terminal Linux.

---

## Licença

Distribuído “como está”, **sem garantia**.

Recomendação: [MIT](https://opensource.org/licenses/MIT) ou [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html). Inclua um arquivo `LICENSE` no repositório.

O autor e os contribuidores **não** se responsabilizam por uso ilegal, perda de dados ou arquivos corrompidos.

---

## Contribuindo

Pull requests são bem-vindos para:

- Detecção de formatos
- Localização de binários do John
- Relatórios e UX do menu
- Traduções
- Correções de bugs

Não serão aceitas contribuições que implementem **bypass** de senha, exploits ou ataque a serviços de terceiros.

---

## Disclaimer (EN)

This project is intended **only** for files you own or are explicitly authorized to audit. It extracts hashes for John the Ripper and can re-encrypt **when the current password is known**. It does not bypass encryption. Misuse is solely the operator’s responsibility.

