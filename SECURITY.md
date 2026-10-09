# SECURITY

Este template prioriza **boas práticas legítimas** para proteção de software .NET:

- **Build determinístico** e Analyzers habilitados;
- **Assinatura de código (Authenticode)** e **validação da assinatura em runtime** (opcional, desativável via config);
- Pipeline **GitHub Actions** para build e publicação de artefatos;
- **Integração opcional** com ofuscadores **comerciais** (ex.: PreEmptive Dotfuscator CE) e **assinatura** com certificado no CI.

> Importante: este repositório **não** inclui anti‑debugging/anti‑VM/packers/ofuscação customizada.
> Essas técnicas podem ser mal utilizadas para ocultar malware. Em vez disso, use **ferramentas comerciais homologadas** para proteger PI
> e combine com política de assinatura, telemetria legal, e gestão de versões.

## Ameaças cobertas parcialmente

- Engenharia reversa passiva (dificultada por assinatura + ReadyToRun/SingleFile e ofuscação comercial);
- Tampering/redistribuição não assinada (mitigado por validação de assinatura);
- Injeção de DLL e hooking: **não coberto** por design aqui;
- Anti‑debugging/anti‑VM: **não implementado** (recomenda‑se ofuscador comercial com recursos específicos).

## Recomendado (comerciais e/ou incluídos no VS)

- **PreEmptive Dotfuscator CE** (vem no Visual Studio): renomeação/flow control/protection básica.
- **Eazfuscator.NET**, **Agile.NET**, **.NET Reactor** (terceiros, comerciais).
- **Assinatura de código** (certificado EV ou org) + timestamping confiável.

