# Catálogo de controles

> Este archivo se genera con `./audit.sh --list-checks`. No lo edites a mano: cambia la tabla `META` del script.

## Cómo leer los niveles

| Nivel | Significado | ¿Resta puntos con `--level 1`? |
|-------|-------------|-------------------------------|
| **N1** | CIS Nivel 1: base razonable para cualquier equipo, con poco impacto operativo | Sí |
| **N2** | CIS Nivel 2: defensa en profundidad; puede afectar el funcionamiento | No: se muestra como recomendación. Excepción: si el riesgo real es alto o crítico, sí cuenta |
| **Extra** | No está en el CIS; se incluye por riesgo real documentado en MITRE ATT&CK | Sí |

El nivel puede cambiar según el **perfil**: por ejemplo, CUPS o Bluetooth activos son N1 en un servidor (no deberían existir) y N2 en una estación de trabajo (imprimir en un portátil es normal).

**Fuentes:** numeración de *CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0*; "(v2)" indica número o nivel de la v2.0.0. Niveles verificados contra la implementación de referencia [ansible-lockdown/UBUNTU24-CIS](https://github.com/ansible-lockdown/UBUNTU24-CIS) y los listados de auditoría de [Tenable](https://www.tenable.com/audits/CIS_Ubuntu_Linux_24.04_LTS_v2.0.0_L2_Server). Debian y Kali comparten la mayoría de los controles; los números pueden variar entre benchmarks.

## Severidad

Independiente del nivel, cada hallazgo tiene una severidad según su **impacto real**: 🟣 crítico (compromiso directo o root inmediato), 🔴 alto, 🟠 medio, 🔵 bajo. El puntaje pondera crítico 10, alto 6, medio 3 y bajo 1; un aviso vale la mitad de un control superado.

Reglas de contexto que ajustan la severidad automáticamente:
- **Riesgo latente:** si SSH está instalado pero apagado y sin arranque automático, sus hallazgos bajan a BAJO.
- **Contexto de paquete:** reglas `sudo` y binarios SUID se atribuyen al paquete que los instaló; lo que no pertenece a ningún paquete se trata como más sospechoso.
- **Alcance real:** una regla `NOPASSWD` para un grupo sin miembros no afecta a nadie hoy y se marca BAJO.

## Controles

| ID | Servidor | Estación | Referencia | Qué verifica |
|----|----|----|----|----|
| SYS-001 | Extra | Extra |  | Datos del equipo auditado |
| SYS-002 | Extra | Extra |  | Ejecución con o sin privilegios de root |
| SYS-003 | Extra | Extra |  | Perfil, nivel CIS y excepciones aplicadas |
| SYS-004 | Extra | Extra |  | Archivo de excepciones protegido contra manipulación |
| UPD-001 | Extra | Extra | CIS v8 7.3 | Lista de paquetes actualizada en los últimos 7 días |
| UPD-002 | N1 | N1 | CIS §1.2.2.1 | Sin actualizaciones pendientes, en especial de seguridad |
| UPD-003 | Extra | Extra | CIS v8 7.3 | Actualizaciones automáticas de seguridad (unattended-upgrades) |
| UPD-004 | Extra | Extra | CIS v8 7.3 | Sin reinicio pendiente para cargar parches |
| ACC-001 | N1 | N1 | CIS §5.4.2.1 | Solo root tiene UID 0 |
| ACC-002 | N1 | N1 | CIS §7.2.5, 7.2.7 | Sin UID ni nombres de usuario duplicados |
| ACC-003 | N1 | N1 | CIS §7.2.2 | Ninguna cuenta con contraseña vacía |
| ACC-004 | N1 | N1 | CIS §5.3.3.4.3 | Ningún hash de contraseña con MD5 o DES |
| ACC-005 | N1 | N1 | CIS §5.4.1.4 | Algoritmo fuerte para contraseñas nuevas (yescrypt o SHA512) |
| ACC-006 | N1 | N1 | CIS §5.3.3.2.2 | Longitud mínima de contraseña de 14 caracteres |
| ACC-007 | N1 | N1 | CIS §5.4.1.1 | Caducidad de contraseñas de 365 días o menos |
| ACC-008 | N1 | N1 | CIS §5.4.2.7 | Cuentas de sistema sin shell de inicio de sesión |
| ACC-009 | N2 | N2 | CIS §5.2.4 | sudo pide contraseña (reglas NOPASSWD) |
| ACC-010 | Extra | Extra | MITRE T1548.003 | Archivos sudoers no modificables por otros |
| ACC-011 | Extra | Extra |  | Inventario de usuarios con sudo |
| ACC-012 | N1 | N1 | CIS §5.4.3.3 | umask por defecto 027 o más restrictiva |
| ACC-013 | Extra | Extra | MITRE T1548.003 | Otras reglas NOPASSWD (informativo) |
| ACC-014 | N1 | N1 | CIS §5.3.2.2 | Bloqueo tras intentos fallidos (pam_faillock) |
| ACC-015 | N1 | N1 | CIS §5.2.2, 5.2.3 | sudo usa pty y registra en un log propio |
| ACC-016 | N1 | N1 | CIS §7.2.4 | El grupo shadow no tiene miembros |
| SSH-000 | Extra | Extra |  | Estado del servicio SSH |
| SSH-001 | N1 | N1 | CIS §5.1.20 | PermitRootLogin no |
| SSH-002 | Extra | Extra | MITRE T1110 | Solo autenticación por llave (no lo exige CIS) |
| SSH-003 | N1 | N1 | CIS §5.1.19 | PermitEmptyPasswords no |
| SSH-004 | N1 | N1 | CIS §5.1.16 | MaxAuthTries 4 o menos |
| SSH-005 | N2 | N1 | CIS §5.1.8 | DisableForwarding yes (sin reenvío X11, de agente ni TCP) |
| SSH-006 | N1 | N1 | CIS §5.1.6, 5.1.12, 5.1.15 | Sin cifrados, MAC ni intercambio de llaves débiles |
| SSH-007 | N1 | N1 | CIS §5.1.21 | PermitUserEnvironment no |
| SSH-008 | N1 | N1 | CIS §5.1.10, 5.1.11 | Sin autenticación por host ni rhosts |
| SSH-009 | N1 | N1 | CIS §5.1.7 | Sesiones inactivas expiran (ClientAliveInterval) |
| SSH-010 | N1 | N1 | CIS §5.1.14 | LogLevel INFO o VERBOSE |
| SSH-011 | N1 | N1 | CIS §5.1.1, 5.1.2 | sshd_config y llaves privadas del servidor protegidas |
| SSH-012 | Extra | Extra | MITRE T1098.004 | authorized_keys no modificables por otros |
| SSH-013 | Extra | Extra | MITRE T1098.004 | Llaves autorizadas de root (informativo) |
| SSH-014 | N1 | N1 | CIS §5.1.13 | LoginGraceTime de 60 segundos o menos |
| SSH-015 | N1 | N1 | CIS §5.1.17, 5.1.18 | MaxSessions 10 o menos y MaxStartups limitado |
| SSH-016 | N2 | N1 | CIS §5.1.9 | GSSAPIAuthentication no |
| SSH-017 | N1 | N1 | CIS §5.1.22 | UsePAM yes |
| FS-001 | N1 | N1 | CIS §7.1.1-7.1.8 | Permisos de passwd, shadow, group, gshadow y sus copias |
| FS-002 | N1 | N1 | CIS §7.1.11 | Ningún archivo de sistema o ejecutable escribible por todos |
| FS-003 | N1 | N1 | CIS §7.1.11 | Otros archivos escribibles por todos |
| FS-004 | N1 | N1 | CIS §7.1.11 | Directorios escribibles por todos con sticky bit |
| FS-005 | N1 | N1 | CIS §7.1.12 | Sin archivos sin dueño o grupo válido |
| FS-006 | Extra | Extra | MITRE T1548.001 | Ningún SUID explotable (nombre, contenido o ubicación) |
| FS-007 | N1 | N1 | CIS §7.1.13 | SUID revisados: atribuidos a un paquete del sistema |
| FS-008 | Extra | Extra |  | Inventario de SUID y SGID |
| FS-009 | N1 | N1 | CIS §1.1.2.1.1-1.1.2.1.4 | /tmp separado con nodev, nosuid y noexec |
| FS-010 | N1 | N1 | CIS §1.1.2.2.1-1.1.2.2.4 | /dev/shm con nodev, nosuid y noexec |
| FS-011 | N1 | N1 | CIS §7.2.9 | Directorios personales no accesibles por otros |
| FS-012 | N1 | N1 | CIS §5.4.2.5 | PATH de root sin '.', rutas relativas ni directorios escribibles |
| KRN-001 | N1 | N1 | CIS §1.5.1 | kernel.randomize_va_space = 2 (ASLR) |
| KRN-002 | N2 | N2 | CIS §1.5.2 (v2) | fs.protected_symlinks = 1 |
| KRN-003 | N1 | N1 | CIS §1.5.1 (v2) | fs.protected_hardlinks = 1 |
| KRN-004 | N1 | N1 | CIS §1.5.3 | fs.suid_dumpable = 0 |
| KRN-005 | N1 | N1 | CIS §1.5.5 (v2) | kernel.dmesg_restrict = 1 |
| KRN-006 | N1 | N1 | CIS §1.5.8 (v2) | kernel.kptr_restrict >= 1 |
| KRN-007 | N1 | N1 | CIS §1.5.2 | kernel.yama.ptrace_scope >= 1 |
| KRN-008 | Extra | Extra | KSPP | kernel.unprivileged_bpf_disabled >= 1 |
| KRN-009 | N2 | N2 | CIS §3.3.1.1 (v2) | net.ipv4.ip_forward = 0 |
| KRN-010 | N1 | N1 | CIS §3.3.2 | No enviar redirecciones ICMP (all y default) |
| KRN-011 | N1 | N1 | CIS §3.3.5 | No aceptar redirecciones ICMP IPv4 (all y default) |
| KRN-012 | N1 | N1 | CIS §3.3.5 | No aceptar redirecciones ICMPv6 (all y default) |
| KRN-013 | N1 | N1 | CIS §3.3.8 | Rechazar paquetes con ruta de origen (all y default) |
| KRN-014 | N1 | N1 | CIS §3.3.7 | Filtro de ruta inversa (rp_filter) activo |
| KRN-015 | N1 | N1 | CIS §3.3.10 | TCP SYN cookies activas |
| KRN-016 | N1 | N1 | CIS §3.3.9 | Registrar paquetes sospechosos (log_martians) |
| KRN-017 | N1 | N1 | CIS §3.3.4 | Ignorar pings a broadcast |
| KRN-018 | N1 | N1 | CIS §3.3.3 | Ignorar respuestas ICMP falsas |
| KRN-019 | N1 | N1 | CIS §3.3.6 | No aceptar redirecciones ICMP 'seguras' |
| KRN-020 | N1 | N1 | CIS §3.3.11 | No aceptar anuncios de router IPv6 (accept_ra) |
| NET-001 | N1 | N1 | CIS §2.1.22 | Solo servicios aprobados escuchan en la red |
| NET-002 | N1 | N1 | CIS §4.1.1, 4.2.x-4.4.x | Firewall activo con política por defecto de bloqueo |
| NET-003 | Extra | Extra | MITRE T1040 | Ninguna interfaz en modo promiscuo |
| LOG-001 | N1 | N1 | CIS §6.1.1.1, 6.1.2.4 | Registros persistentes |
| LOG-002 | N2 | N2 | CIS §6.2.1.1, 6.2.1.2 | auditd instalado y activo |
| LOG-003 | N1 | N1 | CIS §2.3.1.1 | Hora sincronizada por red |
| LOG-004 | N1 | N1 | CIS §6.1.4.1 | Archivos de registro no modificables por otros |
| LOG-005 | Extra | Extra | MITRE T1110 | Intentos de acceso fallidos (últimos 7 días) |
| LOG-006 | Extra | Extra | MITRE T1110 | fail2ban o CrowdSec si SSH está activo |
| LOG-007 | N1 | N1 | CIS §6.3.1, 6.3.2 | AIDE instalado (integridad de archivos) |
| SVC-001 | N1 | N1 | CIS §2.1.6, 2.1.16, 2.1.19 | Sin servidores telnet, rsh, FTP, TFTP ni xinetd |
| SVC-002 | N1 | N1 | CIS §2.1.3-2.1.18 | Servicios de servidor activos justificados |
| SVC-003 | Extra | Extra |  | Servicios systemd con error (informativo) |
| SVC-004 | N1 | N1 | CIS §2.4.1.2-2.4.1.7 | Permisos de /etc/crontab y /etc/cron.* |
| SVC-005 | Extra | Extra | MITRE T1543.002 | Archivos de systemd no modificables por otros |
| SVC-006 | N1 | N1 | CIS §2.2.1-2.2.6 | Clientes inseguros (rsh, telnet, talk, NIS, LDAP, FTP) no instalados |
| SVC-007 | N1 | N2 | CIS §2.1.1, 2.1.2, 2.1.11, 3.1.3 | Servicios de escritorio (avahi, CUPS, autofs, Bluetooth) |
| MAC-001 | N1 | N1 | CIS §1.3.1.1, 1.3.1.2 | AppArmor activo (o SELinux en Enforcing) |
| BOOT-001 | N1 | N1 | CIS §1.4.2 | Configuración de GRUB no legible por otros |
| BOOT-002 | N1 | N1 | CIS §1.4.1 | GRUB protegido con contraseña |
| CNT-001 | Extra | Extra | MITRE T1611 | Miembros del grupo docker (equivale a root) |
| CNT-002 | Extra | Extra | MITRE T1611 | Socket de Docker/Podman no accesible por todos |
| CNT-003 | Extra | Extra | MITRE T1610 | API de Docker no expuesta sin TLS |
