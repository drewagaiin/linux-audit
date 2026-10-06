# Cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [2.1.2] - 2026-10-06

### Corregido
- **FS-002 a FS-007 no recorrían el disco principal cuando "/" no es ext4/xfs/btrfs**
  (por ejemplo overlay en contenedores Docker o zfs). Los SUID peligrosos en
  `/usr/local` pasaban desapercibidos. Lo detectó el CI en Kali, Debian y Ubuntu.
  Ahora "/" se recorre siempre.

## [2.1.1] - 2026-10-06

### Corregido
- CI: aviso SC2002 de ShellCheck 0.9/0.10 (versiones de GitHub Actions) que la
  0.11 ya no reporta. El script se valida ahora con las tres versiones.
- CI: `actions/checkout@v5` (la v4 usaba Node.js 20, ya obsoleto).

## [2.1.0] - 2026-10-06

Revisión completa contra el **CIS Ubuntu Linux 24.04 Benchmark** para que el
informe sea justo: que la prioridad refleje el riesgo real.

### Añadido
- Nivel CIS (N1/N2) y regla del benchmark en cada control, con perfil
  servidor/estación de trabajo (`--profile`, detección automática).
- `--level 1|2`: con nivel 1, los controles de Nivel 2 de riesgo medio o bajo
  se muestran como recomendaciones y no restan puntos.
- Registro de riesgos aceptados (`--exceptions`, `/etc/linux-audit/exceptions.conf`)
  protegido contra manipulación (SYS-004).
- `--list-checks`: el catálogo `docs/CHECKS.md` se genera desde el script.
- Riesgo latente: con SSH apagado, sus hallazgos bajan a BAJO (SSH-000).
- Atribución a paquetes: reglas `sudo` y binarios SUID muestran qué paquete los
  instaló; un SUID sin paquete es ALTO (FS-007). Soporta rutas usr-merge.
- Nuevos controles CIS Nivel 1: bloqueo por intentos fallidos (ACC-014), sudo
  con pty y log (ACC-015), grupo shadow vacío (ACC-016), LoginGraceTime (SSH-014),
  MaxSessions/MaxStartups (SSH-015), GSSAPI (SSH-016), UsePAM (SSH-017),
  AIDE (LOG-007), clientes inseguros (SVC-006), servicios de escritorio (SVC-007),
  y sysctl de ICMP falsos, redirecciones seguras y accept_ra (KRN-018 a 020).

### Cambiado
- SSH-006 usa las listas de algoritmos débiles del CIS: `hmac-sha1` ya no se
  marca (CIS lo permite); `umac-64` sí.
- SSH-005 evalúa `DisableForwarding` (CIS 5.1.8) en lugar de solo X11.
- SSH-001 con llave (`prohibit-password`) baja de ALTO a MEDIO: no hay fuerza
  bruta posible, el riesgo es de trazabilidad.
- SSH-002 pasa de FALLO a AVISO: no lo exige el CIS (sí otras guías).
- Los sysctl revisan las variantes `all` y `default`, como pide el CIS.
- ACC-008 reconoce cuentas con contraseña bloqueada y las creadas así por
  diseño (postgres).
- UPD-003 no recomienda actualizaciones automáticas en Kali (rolling).
- LOG-003 reconoce la sincronización de hora del hipervisor (VirtualBox, VMware).
- FS-009/FS-010 advierten que `noexec` puede afectar instaladores.

## [2.0.2] - 2026-10-06

### Cambiado
- ACC-009 evalúa el riesgo real de cada regla `NOPASSWD`:
  - `NOPASSWD: ALL` para usuarios o grupos con miembros → ALTO.
  - Limitada a comandos concretos → MEDIO (revisar con GTFOBins).
  - Para un grupo sin miembros (ej. `%kali-trusted` en Kali) → BAJO.
  Antes todo se marcaba ALTO, lo que exageraba el riesgo en Kali.

## [2.0.1] - 2026-10-06

### Corregido
- UPD-002: falso positivo con paquetes que contienen "security" en el nombre
  (ej. `libfalcosecurity0t64` en Kali). Ahora solo se mira el repositorio de origen.
- UPD-002: 50 o más actualizaciones pendientes se marcan como ALTO, no MEDIO
  (caso típico de Kali y otras distribuciones rolling sin actualizar).

## [2.0.0] - 2026-10-06

### Añadido
- Más de 70 controles en 12 categorías (antes 10 pruebas generales).
- Severidad por hallazgo (crítico, alto, medio, bajo) y puntaje ponderado.
- Referencias a CIS Critical Security Controls v8 y MITRE ATT&CK.
- Salida JSON e informe HTML autocontenido.
- Opciones `--only`, `--fail-on`, `--quiet` y `--format`.
- Detección de SUID explotables por nombre (GTFOBins), por contenido (copias renombradas) y por ubicación; también en `/tmp` y `/dev/shm` montados como tmpfs.
- Parámetros del kernel (17 controles sysctl).
- Criptografía débil en SSH, `authorized_keys`, llaves del servidor.
- auditd, sincronización de hora, AppArmor/SELinux, GRUB, Docker.
- Pruebas automatizadas con Bats, incluidas pruebas que siembran vulnerabilidades reales.
- CI en Kali Rolling, Debian 12, Ubuntu 22.04 y 24.04.

### Seguridad
- `PATH` fijo y `LC_ALL=C` al ejecutarse con sudo.
- Informes con permisos `600` (`umask 077`) y rechazo de enlaces simbólicos en `--output`.
- `/etc/os-release` se lee como texto en lugar de ejecutarse con `source`.
- Escapado HTML corregido para Bash 5.2+ (`patsub_replacement`).

### Eliminado
- Prueba de espacio en disco (no es un control de seguridad).

## [1.0.0] - 2026-10-06
- Versión inicial: 10 pruebas básicas con salida de texto.
