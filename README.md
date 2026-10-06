# 🛡️ linux-audit

**Auditoría de seguridad de solo lectura para servidores Linux, mapeada a CIS Controls v8 y MITRE ATT&CK.**

Un solo script en Bash, sin dependencias, que revisa más de 85 controles alineados con el **CIS Ubuntu Linux 24.04 Benchmark** y entrega un informe priorizado por severidad, en texto, JSON (para SIEM y pipelines) o HTML (para entregar a un cliente o a gerencia).

[![CI](https://github.com/drewagaiin/linux-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/drewagaiin/linux-audit/actions/workflows/ci.yml)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-blue)
![Bash 4+](https://img.shields.io/badge/bash-4%2B-green)
![Probado en Kali · Debian · Ubuntu](https://img.shields.io/badge/probado-Kali%20%C2%B7%20Debian%20%C2%B7%20Ubuntu-informational)

---

## Por qué

En la mayoría de pymes nadie revisa la configuración de los servidores hasta que hay un incidente. Las herramientas completas (OpenSCAP, Wazuh, Lynis) son excelentes, pero requieren instalación, perfiles y tiempo. `linux-audit` responde en segundos a la pregunta **"¿qué es lo más urgente de arreglar en este servidor?"**, y para cada hallazgo dice **por qué importa y cómo corregirlo**.

## Características

- **Más de 85 controles** en 12 áreas: cuentas, SSH, permisos, SUID, kernel, firewall, registros, servicios, AppArmor/SELinux, arranque y contenedores. Ver el [catálogo completo](docs/CHECKS.md).
- **Niveles y perfiles del CIS**: cada control indica su regla y nivel CIS (N1/N2) para servidor o estación de trabajo. Los de Nivel 2 se muestran como recomendaciones y no penalizan, salvo que el riesgo real sea alto.
- **Un informe justo, no alarmista**: un hallazgo de SSH con el servicio apagado es un riesgo latente; una regla `sudo` de OpenVAS se reconoce como necesaria; un SUID se atribuye al paquete que lo instaló. Así la prioridad refleja el riesgo real.
- **Registro de riesgos aceptados**: documenta las excepciones con su motivo; aparecen como ACEPTADO y el archivo está protegido contra manipulación.
- **Severidad real** (crítico, alto, medio, bajo) y **puntaje ponderado**: un usuario oculto con UID 0 no pesa lo mismo que un banner de SSH.
- **Referencias a estándares** en cada hallazgo: CIS Ubuntu 24.04 Benchmark, CIS Critical Security Controls v8 y MITRE ATT&CK.
- **Tres formatos**: texto con colores, JSON estructurado e informe HTML autocontenido con modo oscuro.
- **Listo para automatizar**: `--fail-on high` devuelve código 1 solo si hay fallos altos o críticos (ideal para CI/CD, cron o Ansible).
- **Seguro por diseño**: nunca modifica el sistema (verificado por pruebas), no usa la red, fija un `PATH` seguro, escribe informes con permisos `600` y rechaza rutas que sean enlaces simbólicos.
- **Probado de verdad**: las pruebas automatizadas siembran vulnerabilidades reales (puertas traseras UID 0, SUID explotables, `shadow` legible, sudo sin contraseña…) y verifican que se detectan, en Kali, Debian 12 y Ubuntu 22.04/24.04.

## Uso rápido

```bash
git clone https://github.com/drewagaiin/linux-audit.git
cd linux-audit
sudo ./audit.sh
```

```text
== SSH ==
  [FALLO]   SSH-001  root puede entrar por SSH con contraseña (PermitRootLogin yes) (ALTO)
                     Es el primer usuario que prueban los bots de fuerza bruta.
                     → En sshd_config: PermitRootLogin no
  [FALLO]   SSH-006  Algoritmos criptográficos débiles habilitados en SSH (MEDIO)
                     mac:hmac-sha1, mac:umac-64@openssh.com
  [OK]      SSH-003  PermitEmptyPasswords no

== Resumen ==
  Puntaje: 70/100   (ponderado por severidad)
  OK 35 · Avisos 12 · Fallos 18 · Omitidas 4 · Informativas 4
  Problemas por severidad: CRÍTICO 1 · ALTO 5 · MEDIO 13 · BAJO 11

  Prioridad: corrige primero los CRÍTICOS y ALTOS:
   - FS-006   Binarios SUID que permiten volverse root
   - ACC-009  Reglas sudo sin contraseña (NOPASSWD)
   - SSH-001  root puede entrar por SSH con contraseña (PermitRootLogin yes)
   - NET-002  No hay firewall activo
   - UPD-002  26 actualizaciones de SEGURIDAD pendientes (28 en total)
   - CNT-001  Usuarios en el grupo docker: deploy
```

## Ejemplos

```bash
# Informe HTML para entregar (se crea con permisos 600)
sudo ./audit.sh -f html -o informe-$(hostname)-$(date +%F).html

# JSON para procesar o enviar a un SIEM
sudo ./audit.sh -f json | jq '.findings[] | select(.status == "FAIL") | {id, severity, title}'

# Solo SSH y kernel, mostrando únicamente problemas
sudo ./audit.sh --only ssh,krn --quiet

# En un pipeline: falla solo si hay hallazgos altos o críticos
sudo ./audit.sh --fail-on high -f json -o resultado.json

# Auditoría semanal con cron (lunes 6:00)
0 6 * * 1  /opt/linux-audit/audit.sh -f json -o /var/log/linux-audit/$(date +\%F).json
```

## Opciones

| Opción | Descripción |
|--------|-------------|
| `-f, --format` | `text` (por defecto), `json` o `html` |
| `-o, --output ARCHIVO` | Escribe el informe en un archivo con permisos `600` |
| `--only CATS` | Categorías separadas por comas: `sys,upd,acc,ssh,fs,krn,net,log,svc,mac,boot,cnt` |
| `--fail-on SEV` | Severidad mínima que provoca código de salida 1: `low` (defecto), `medium`, `high`, `critical` |
| `--level N` | Nivel CIS a exigir: `1` (base, por defecto) o `2` (defensa en profundidad) |
| `--profile P` | `server` o `workstation`; por defecto se detecta (entorno gráfico = estación) |
| `--exceptions FILE` | Registro de riesgos aceptados (por defecto `/etc/linux-audit/exceptions.conf` si existe). Ver [ejemplo](docs/exceptions.example.conf) |
| `--list-checks` | Lista todos los controles con su nivel CIS y referencia |
| `-q, --quiet` | Solo avisos, fallos y resumen |
| `--no-color` | Sin colores |

**Códigos de salida:** `0` sin fallos al nivel de `--fail-on` · `1` hay fallos · `2` error de uso.

## Un informe justo: cómo se decide la prioridad

Una herramienta que marca todo como urgente termina siendo ignorada. Por eso `linux-audit` aplica cuatro reglas, todas cubiertas por pruebas:

| Regla | Ejemplo |
|-------|---------|
| **Nivel CIS** | `auditd` es CIS Nivel 2: con `--level 1` aparece como recomendación opcional, no como fallo |
| **Perfil** | CUPS activo es un problema en un servidor, pero normal en el portátil de un empleado |
| **Riesgo latente** | Si SSH está apagado, `PermitRootLogin yes` sigue apareciendo, pero como BAJO |
| **Contexto de paquete** | La regla `NOPASSWD` de OpenVAS se identifica como necesaria para el escáner; un SUID sin paquete se marca ALTO |

Cuando el riesgo real es alto, ninguna regla lo oculta: `NOPASSWD: ALL` para un usuario activo es Nivel 2 en el CIS, pero se reporta como ALTO y el informe explica por qué.

## Formato JSON

```json
{
  "tool": "linux-audit", "version": "2.0.0", "host": "srv-web-01",
  "timestamp": "2026-10-06T12:00:00Z", "run_as_root": true,
  "profile": "server", "cis_level": 1, "score": 70,
  "summary": {"pass": 35, "warn": 12, "fail": 18, "level2": 2, "accepted": 1,
              "critical": 1, "high": 5, "medium": 13, "low": 11},
  "findings": [
    {"id": "SSH-001", "category": "SSH", "status": "FAIL", "severity": "high", "cis_level": "CIS N1",
     "title": "root puede entrar por SSH con contraseña (PermitRootLogin yes)",
     "detail": "...", "remediation": "En sshd_config: PermitRootLogin no",
     "references": "CIS Ubuntu 24.04 §5.1.20 · CIS v8 5.4 · MITRE T1110"}
  ]
}
```

Estados posibles: `FAIL`, `WARN`, `L2` (recomendación de Nivel 2), `ACCEPT` (riesgo aceptado), `PASS`, `INFO` y `SKIP`. Los ID son estables entre versiones, así que puedes comparar auditorías en el tiempo.

## Seguridad del propio script

| Riesgo | Mitigación |
|--------|------------|
| Secuestro de binarios al correr con `sudo` | `PATH` fijo y seguro; el `PATH` original solo se audita |
| Ejecución de código al leer configuraciones | `/etc/os-release` y demás se leen como texto, nunca con `source` |
| Informe legible por otros usuarios | `umask 077`: los informes se crean con permisos `600` |
| Ataque de enlace simbólico en `-o` | Se rechaza cualquier ruta de salida que sea un enlace simbólico |
| Inyección en el informe HTML/JSON por nombres de archivo maliciosos | Escapado completo, cubierto por pruebas |
| Fuga de secretos | Nunca se imprimen hashes de contraseña ni contenido de llaves |
| Ocultar hallazgos con un archivo de excepciones falso | Como root, solo se acepta un archivo de root no modificable por otros; si no, se ignora y se reporta (SYS-004) |
| Recorridos de disco interminables | `timeout` en cada recorrido; solo sistemas de archivos locales |

## Pruebas

```bash
bats tests/cli.bats      # seguras: interfaz, formatos, garantía de solo lectura, escapado

# ⚠️ Solo en VM desechables o snapshots: siembran vulnerabilidades reales
sudo LINUX_AUDIT_DESTRUCTIVE_TESTS=1 bats tests/detection.bats
```

El CI ejecuta ambas en contenedores de **Kali Rolling, Debian 12, Ubuntu 22.04 y 24.04** en cada push, además de ShellCheck.

## Alcance y limitaciones

`linux-audit` es una **revisión rápida de configuración**, no un escáner de vulnerabilidades ni una prueba de penetración. No reemplaza a OpenSCAP para certificar cumplimiento CIS formal, ni a un EDR/SIEM para detectar intrusiones activas. Distribuciones con `dnf`/`yum` funcionan, pero las pruebas de actualizaciones se omiten por ahora.

## Uso responsable

Ejecuta esta herramienta solo en equipos propios o con autorización explícita y por escrito. Los informes describen debilidades del equipo: trátalos como información confidencial.

## Hoja de ruta

- [ ] Soporte de `dnf` (Fedora, RHEL, Rocky)
- [ ] Comparar dos informes JSON (`--diff`)
- [ ] Reglas de `auditd` recomendadas por CIS
- [ ] Exportar en formato SARIF

## Licencia

[MIT](LICENSE) · Ver también [SECURITY.md](SECURITY.md) y [CHANGELOG.md](CHANGELOG.md).
