# Template C# Seguro (.NET 8) — por MicDog (Michael Douglas)

Template profissional para projetos C# com **hardening legítimo**: build determinístico, validação de **assinatura de código (Authenticode)** em runtime, Analyzers, pipeline GitHub Actions e pontos de integração para **ofuscadores comerciais** (ex.: PreEmptive Dotfuscator CE do Visual Studio).

> ⚠️ Ética & Legal: este projeto **não** inclui técnicas de anti‑debugging/anti‑VM/ofuscação customizada, que podem ser usadas para fins maliciosos.
> Para proteger propriedade intelectual, use soluções comerciais homologadas e **assinatura de código**.

---

## Principais recursos

- [.NET 8](https://dotnet.microsoft.com/) — Console app
- Build **determinístico** e **analyzers** habilitados
- **Validação de assinatura Authenticode** em runtime (opcional)
- Pipeline **GitHub Actions** para build e artefatos
- **Integração opcional** com ofuscadores comerciais (ex.: Dotfuscator CE)

## Como usar

1. **Clonar** e restaurar:
   ```bash
   dotnet restore
   dotnet build -c Release
   ```

2. (Opcional) **Assinar** o binário localmente:
   ```powershell
   # Ajuste o caminho do certificado e o sujeito
   signtool sign ^
     /fd SHA256 /td SHA256 ^
     /tr http://timestamp.digicert.com ^
     /f .\certs\seu_certificado.pfx /p SUA_SENHA ^
     .\src\SecureApp\bin\Release\net8.0-windows\SecureApp.exe
   ```

3. **Executar**:
   ```bash
   src/SecureApp/bin/Release/net8.0-windows/SecureApp.exe
   ```

4. **Configurar validação de assinatura** (arquivo `secure.json` na mesma pasta do exe):
   ```json
   {
     "enforceSignature": true,
     "allowedPublisherCn": [
       "CN=MicDog (Michael Douglas)"
     ]
   }
   ```
   - Se `enforceSignature` for `true`, o app só continua se o executável estiver **assinado** e o **CN** do emissor corresponder a um dos itens de `allowedPublisherCn` (se a lista não estiver vazia).
   - Se `false` (padrão no Dev), apenas registra um aviso.

## Ofuscação (opcional)

- **PreEmptive Dotfuscator CE** (incluso no Visual Studio 2022)
  - Menu: **Ferramentas → PreEmptive Protection - Dotfuscator**
  - Crie uma configuração e referencie-a na etapa de empacotamento.
- Alternativas comerciais: **Eazfuscator.NET**, **Agile.NET**, **.NET Reactor**.

> Observação: ofuscação pode quebrar reflexão; teste bem.

## CI/CD — GitHub Actions

O fluxo padrão compila o projeto em Release e publica artefatos. Você pode estender para assinar no CI
usando segredos (`CERT_BASE64`, `CERT_PASSWORD`) e um passo de `signtool` em um runner Windows.

## Licença

MIT © 2025 **MicDog (Michael Douglas)** — veja [LICENSE](LICENSE).

