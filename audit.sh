#!/usr/bin/env bash
# =============================================================================
#  linux-audit v2 — Auditoría de seguridad de solo lectura para Linux
#
#  Mapeado a CIS Critical Security Controls v8 y MITRE ATT&CK.
#  Probado en: Kali Linux, Debian 12, Ubuntu 22.04/24.04.
#  Licencia: MIT
#
#  GARANTÍA DE DISEÑO: este script NUNCA modifica el sistema auditado.
#  No instala paquetes, no cambia configuraciones y no se conecta a la red.
# =============================================================================

set -uo pipefail

# --- Endurecimiento del propio script ----------------------------------------
# Al ejecutarse con sudo, un PATH manipulado podría hacer que llamemos a un
# binario falso. Guardamos el PATH original (para auditarlo) y fijamos uno seguro.
ORIG_PATH="${PATH:-}"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Salida de comandos en inglés y formato estable para poder analizarla.
export LC_ALL=C
# Los informes revelan debilidades del equipo: solo el dueño puede leerlos.
umask 077
# En Bash 5.2+ '&' en ${var//a/b} significa "el texto encontrado". Lo desactivamos
# para que los escapes HTML (&lt; &amp;) funcionen igual en todas las versiones.
shopt -u patsub_replacement 2>/dev/null || true

readonly VERSION="2.1.1"

# --- Opciones -----------------------------------------------------------------
FORMAT="text"        # text | json | html
OUTPUT_FILE=""
USE_COLOR=1
QUIET=0
FAIL_ON="low"        # severidad mínima que provoca código de salida 1
ONLY=""              # categorías a ejecutar (vacío = todas)
FIND_TIMEOUT=300     # segundos máximos para recorrer el disco
LEVEL=1              # nivel CIS a exigir: 1 (base) o 2 (defensa en profundidad)
PROFILE=""           # server | workstation (vacío = detectar automáticamente)
PROFILE_WHY=""
EXC_FILE=""          # archivo de riesgos aceptados
EXC_WARN=""
SSH_LATENT=0
declare -A EXC=()

# --- Almacén de resultados ------------------------------------------------------
R_ID=(); R_CAT=(); R_STATUS=(); R_SEV=(); R_TITLE=(); R_DETAIL=(); R_FIX=(); R_REF=(); R_LVL=()
LAST_CAT=""
C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_GRY=""; C_BLD=""; C_RST=""

IS_ROOT=0
[[ $EUID -eq 0 ]] && IS_ROOT=1

# =============================================================================
#  Utilidades
# =============================================================================

usage() {
    cat <<EOF
linux-audit v${VERSION} — Auditoría de seguridad de solo lectura

Uso: sudo $0 [opciones]

Opciones:
  -f, --format FORMATO   text (por defecto), json o html
  -o, --output ARCHIVO   Escribe el informe en ARCHIVO (permisos 600)
      --only CATS        Solo estas categorías, separadas por comas:
                         sys,upd,acc,ssh,fs,krn,net,log,svc,mac,boot,cnt
      --fail-on SEV      Devuelve código 1 solo si hay fallos de esta
                         severidad o mayor: low|medium|high|critical (def: low)
      --level N          Nivel CIS a exigir: 1 (base, por defecto) o 2
                         (defensa en profundidad). Con nivel 1, los controles
                         de nivel 2 se muestran como recomendaciones.
      --profile P        server o workstation (por defecto se detecta: si hay
                         entorno gráfico es workstation)
      --exceptions FILE  Riesgos aceptados: una línea por control, "ID motivo"
                         (por defecto /etc/linux-audit/exceptions.conf si existe)
      --list-checks      Lista todos los controles con su nivel CIS y sale
  -q, --quiet            Muestra solo avisos, fallos y el resumen
      --no-color         Sin colores
  -h, --help             Esta ayuda
  -v, --version          Versión

Códigos de salida:
  0  Sin fallos al nivel de --fail-on
  1  Hay fallos al nivel de --fail-on o superior
  2  Error de uso

Ejemplos:
  sudo $0
  sudo $0 -f html -o informe.html
  sudo $0 -f json | jq '.findings[] | select(.status=="FAIL")'
  sudo $0 --only ssh,krn --fail-on high
  sudo $0 --level 2 --profile server
EOF
}

die() { printf 'Error: %s\n' "$1" >&2; exit 2; }

have() { command -v "$1" >/dev/null 2>&1; }

# Número de severidad para comparar
sev_num() {
    case "$1" in
        critical) echo 4 ;; high) echo 3 ;; medium) echo 2 ;; low) echo 1 ;; *) echo 0 ;;
    esac
}

# Peso de cada severidad en el puntaje
sev_weight() {
    case "$1" in
        critical) echo 10 ;; high) echo 6 ;; medium) echo 3 ;; low) echo 1 ;; *) echo 0 ;;
    esac
}

sev_label() {
    case "$1" in
        critical) echo "CRÍTICO" ;; high) echo "ALTO" ;; medium) echo "MEDIO" ;;
        low) echo "BAJO" ;; *) echo "INFO" ;;
    esac
}

status_label() {
    case "$1" in
        PASS) echo "OK" ;; WARN) echo "AVISO" ;; FAIL) echo "FALLO" ;;
        SKIP) echo "OMITIDA" ;; L2) echo "NIVEL 2" ;; ACCEPT) echo "ACEPTADO" ;;
        *) echo "INFO" ;;
    esac
}

cat_label() {
    case "$1" in
        SYS) echo "Sistema" ;; UPD) echo "Actualizaciones" ;;
        ACC) echo "Cuentas y contraseñas" ;; SSH) echo "SSH" ;;
        FS) echo "Sistema de archivos" ;; KRN) echo "Kernel (sysctl)" ;;
        NET) echo "Red y firewall" ;; LOG) echo "Registros y auditoría" ;;
        SVC) echo "Servicios y tareas programadas" ;;
        MAC) echo "Control de acceso obligatorio" ;; BOOT) echo "Arranque" ;;
        CNT) echo "Contenedores" ;; *) echo "$1" ;;
    esac
}

# Nombre del sistema operativo. Leemos /etc/os-release como texto en lugar de
# ejecutarlo con 'source': un archivo ejecutado como root podría correr código.
os_name() {
    local n=""
    [[ -r /etc/os-release ]] && n=$(sed -n 's/^PRETTY_NAME=["'\'']\{0,1\}\([^"'\'']*\).*/\1/p' /etc/os-release | head -n1)
    printf '%s' "${n:-desconocido}"
}

# Lee un valor de /proc/sys a partir de su nombre sysctl (a.b.c -> a/b/c)
sysctl_get() {
    local f="/proc/sys/${1//.//}"
    [[ -r "$f" ]] && head -n1 "$f" 2>/dev/null
}

# Valor de una clave en un archivo "CLAVE VALOR" (login.defs, pwquality.conf)
conf_get() {
    local file=$1 key=$2
    [[ -r "$file" ]] || return 0
    awk -v k="$key" '
        $0 ~ /^[[:space:]]*#/ { next }
        { sub(/=/, " ") }
        $1 == k { v = $2 }
        END { if (v != "") print v }' "$file"
}

# Paquete que instaló un archivo (vacío si ninguno: eso ya es sospechoso)
# En sistemas con usr-merge (/bin -> /usr/bin) dpkg puede tener registrada la
# ruta antigua, así que se prueban ambas para no dar falsos "huérfanos".
pkg_of() {
    have dpkg-query || return 0
    local f=$1 alt="" out
    case "$f" in
        /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) alt=${f#/usr} ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*) alt=/usr$f ;;
    esac
    out=$(dpkg-query -S -- "$f" 2>/dev/null | head -n1)
    [[ -z "$out" && -n "$alt" ]] && out=$(dpkg-query -S -- "$alt" 2>/dev/null | head -n1)
    printf '%s' "${out%%:*}"
}

# Une líneas en una lista separada por comas, máximo N elementos
join_list() {
    local max=${1:-10}
    awk -v m="$max" 'NF { n++; if (n <= m) a = a (n > 1 ? ", " : "") $0 }
        END { if (n > m) a = a " (+" n - m " más)"; print a }'
}

# =============================================================================
#  Catálogo de controles: nivel CIS y referencia
# =============================================================================
# Formato: "SW|referencia|descripción"
#   S = nivel CIS en perfil Servidor, W = nivel en perfil Estación de trabajo
#   1 = Nivel 1 (base razonable para todos)  2 = Nivel 2 (defensa en profundidad)
#   X = control extra de linux-audit, basado en riesgo real (MITRE ATT&CK)
# Numeración: CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0; "(v2)" indica que el
# número o el nivel provienen de la v2.0.0. Fuente de niveles: implementación
# de referencia ansible-lockdown/UBUNTU24-CIS y listados de auditoría de Tenable.
declare -A META=(
  [SYS-001]="XX||Datos del equipo auditado"
  [SYS-002]="XX||Ejecución con o sin privilegios de root"
  [SYS-003]="XX||Perfil, nivel CIS y excepciones aplicadas"
  [SYS-004]="XX||Archivo de excepciones protegido contra manipulación"
  [UPD-001]="XX|CIS v8 7.3|Lista de paquetes actualizada en los últimos 7 días"
  [UPD-002]="11|1.2.2.1|Sin actualizaciones pendientes, en especial de seguridad"
  [UPD-003]="XX|CIS v8 7.3|Actualizaciones automáticas de seguridad (unattended-upgrades)"
  [UPD-004]="XX|CIS v8 7.3|Sin reinicio pendiente para cargar parches"
  [ACC-001]="11|5.4.2.1|Solo root tiene UID 0"
  [ACC-002]="11|7.2.5, 7.2.7|Sin UID ni nombres de usuario duplicados"
  [ACC-003]="11|7.2.2|Ninguna cuenta con contraseña vacía"
  [ACC-004]="11|5.3.3.4.3|Ningún hash de contraseña con MD5 o DES"
  [ACC-005]="11|5.4.1.4|Algoritmo fuerte para contraseñas nuevas (yescrypt o SHA512)"
  [ACC-006]="11|5.3.3.2.2|Longitud mínima de contraseña de 14 caracteres"
  [ACC-007]="11|5.4.1.1|Caducidad de contraseñas de 365 días o menos"
  [ACC-008]="11|5.4.2.7|Cuentas de sistema sin shell de inicio de sesión"
  [ACC-009]="22|5.2.4|sudo pide contraseña (reglas NOPASSWD)"
  [ACC-010]="XX|MITRE T1548.003|Archivos sudoers no modificables por otros"
  [ACC-011]="XX||Inventario de usuarios con sudo"
  [ACC-012]="11|5.4.3.3|umask por defecto 027 o más restrictiva"
  [ACC-013]="XX|MITRE T1548.003|Otras reglas NOPASSWD (informativo)"
  [ACC-014]="11|5.3.2.2|Bloqueo tras intentos fallidos (pam_faillock)"
  [ACC-015]="11|5.2.2, 5.2.3|sudo usa pty y registra en un log propio"
  [ACC-016]="11|7.2.4|El grupo shadow no tiene miembros"
  [SSH-000]="XX||Estado del servicio SSH"
  [SSH-001]="11|5.1.20|PermitRootLogin no"
  [SSH-002]="XX|MITRE T1110|Solo autenticación por llave (no lo exige CIS)"
  [SSH-003]="11|5.1.19|PermitEmptyPasswords no"
  [SSH-004]="11|5.1.16|MaxAuthTries 4 o menos"
  [SSH-005]="21|5.1.8|DisableForwarding yes (sin reenvío X11, de agente ni TCP)"
  [SSH-006]="11|5.1.6, 5.1.12, 5.1.15|Sin cifrados, MAC ni intercambio de llaves débiles"
  [SSH-007]="11|5.1.21|PermitUserEnvironment no"
  [SSH-008]="11|5.1.10, 5.1.11|Sin autenticación por host ni rhosts"
  [SSH-009]="11|5.1.7|Sesiones inactivas expiran (ClientAliveInterval)"
  [SSH-010]="11|5.1.14|LogLevel INFO o VERBOSE"
  [SSH-011]="11|5.1.1, 5.1.2|sshd_config y llaves privadas del servidor protegidas"
  [SSH-012]="XX|MITRE T1098.004|authorized_keys no modificables por otros"
  [SSH-013]="XX|MITRE T1098.004|Llaves autorizadas de root (informativo)"
  [SSH-014]="11|5.1.13|LoginGraceTime de 60 segundos o menos"
  [SSH-015]="11|5.1.17, 5.1.18|MaxSessions 10 o menos y MaxStartups limitado"
  [SSH-016]="21|5.1.9|GSSAPIAuthentication no"
  [SSH-017]="11|5.1.22|UsePAM yes"
  [FS-001]="11|7.1.1-7.1.8|Permisos de passwd, shadow, group, gshadow y sus copias"
  [FS-002]="11|7.1.11|Ningún archivo de sistema o ejecutable escribible por todos"
  [FS-003]="11|7.1.11|Otros archivos escribibles por todos"
  [FS-004]="11|7.1.11|Directorios escribibles por todos con sticky bit"
  [FS-005]="11|7.1.12|Sin archivos sin dueño o grupo válido"
  [FS-006]="XX|MITRE T1548.001|Ningún SUID explotable (nombre, contenido o ubicación)"
  [FS-007]="11|7.1.13|SUID revisados: atribuidos a un paquete del sistema"
  [FS-008]="XX||Inventario de SUID y SGID"
  [FS-009]="11|1.1.2.1.1-1.1.2.1.4|/tmp separado con nodev, nosuid y noexec"
  [FS-010]="11|1.1.2.2.1-1.1.2.2.4|/dev/shm con nodev, nosuid y noexec"
  [FS-011]="11|7.2.9|Directorios personales no accesibles por otros"
  [FS-012]="11|5.4.2.5|PATH de root sin '.', rutas relativas ni directorios escribibles"
  [KRN-001]="11|1.5.1|kernel.randomize_va_space = 2 (ASLR)"
  [KRN-002]="22|1.5.2 (v2)|fs.protected_symlinks = 1"
  [KRN-003]="11|1.5.1 (v2)|fs.protected_hardlinks = 1"
  [KRN-004]="11|1.5.3|fs.suid_dumpable = 0"
  [KRN-005]="11|1.5.5 (v2)|kernel.dmesg_restrict = 1"
  [KRN-006]="11|1.5.8 (v2)|kernel.kptr_restrict >= 1"
  [KRN-007]="11|1.5.2|kernel.yama.ptrace_scope >= 1"
  [KRN-008]="XX|KSPP|kernel.unprivileged_bpf_disabled >= 1"
  [KRN-009]="22|3.3.1.1 (v2)|net.ipv4.ip_forward = 0"
  [KRN-010]="11|3.3.2|No enviar redirecciones ICMP (all y default)"
  [KRN-011]="11|3.3.5|No aceptar redirecciones ICMP IPv4 (all y default)"
  [KRN-012]="11|3.3.5|No aceptar redirecciones ICMPv6 (all y default)"
  [KRN-013]="11|3.3.8|Rechazar paquetes con ruta de origen (all y default)"
  [KRN-014]="11|3.3.7|Filtro de ruta inversa (rp_filter) activo"
  [KRN-015]="11|3.3.10|TCP SYN cookies activas"
  [KRN-016]="11|3.3.9|Registrar paquetes sospechosos (log_martians)"
  [KRN-017]="11|3.3.4|Ignorar pings a broadcast"
  [KRN-018]="11|3.3.3|Ignorar respuestas ICMP falsas"
  [KRN-019]="11|3.3.6|No aceptar redirecciones ICMP 'seguras'"
  [KRN-020]="11|3.3.11|No aceptar anuncios de router IPv6 (accept_ra)"
  [NET-001]="11|2.1.22|Solo servicios aprobados escuchan en la red"
  [NET-002]="11|4.1.1, 4.2.x-4.4.x|Firewall activo con política por defecto de bloqueo"
  [NET-003]="XX|MITRE T1040|Ninguna interfaz en modo promiscuo"
  [LOG-001]="11|6.1.1.1, 6.1.2.4|Registros persistentes"
  [LOG-002]="22|6.2.1.1, 6.2.1.2|auditd instalado y activo"
  [LOG-003]="11|2.3.1.1|Hora sincronizada por red"
  [LOG-004]="11|6.1.4.1|Archivos de registro no modificables por otros"
  [LOG-005]="XX|MITRE T1110|Intentos de acceso fallidos (últimos 7 días)"
  [LOG-006]="XX|MITRE T1110|fail2ban o CrowdSec si SSH está activo"
  [LOG-007]="11|6.3.1, 6.3.2|AIDE instalado (integridad de archivos)"
  [SVC-001]="11|2.1.6, 2.1.16, 2.1.19|Sin servidores telnet, rsh, FTP, TFTP ni xinetd"
  [SVC-002]="11|2.1.3-2.1.18|Servicios de servidor activos justificados"
  [SVC-003]="XX||Servicios systemd con error (informativo)"
  [SVC-004]="11|2.4.1.2-2.4.1.7|Permisos de /etc/crontab y /etc/cron.*"
  [SVC-005]="XX|MITRE T1543.002|Archivos de systemd no modificables por otros"
  [SVC-006]="11|2.2.1-2.2.6|Clientes inseguros (rsh, telnet, talk, NIS, LDAP, FTP) no instalados"
  [SVC-007]="12|2.1.1, 2.1.2, 2.1.11, 3.1.3|Servicios de escritorio (avahi, CUPS, autofs, Bluetooth)"
  [MAC-001]="11|1.3.1.1, 1.3.1.2|AppArmor activo (o SELinux en Enforcing)"
  [BOOT-001]="11|1.4.2|Configuración de GRUB no legible por otros"
  [BOOT-002]="11|1.4.1|GRUB protegido con contraseña"
  [CNT-001]="XX|MITRE T1611|Miembros del grupo docker (equivale a root)"
  [CNT-002]="XX|MITRE T1611|Socket de Docker/Podman no accesible por todos"
  [CNT-003]="XX|MITRE T1610|API de Docker no expuesta sin TLS"
)

# Perfil CIS: estación de trabajo si hay un gestor de inicio de sesión gráfico
detect_profile() {
    local dm
    if have systemctl && systemctl is-active --quiet display-manager 2>/dev/null; then
        PROFILE=workstation; PROFILE_WHY="entorno gráfico activo"; return
    fi
    for dm in gdm3 gdm lightdm sddm lxdm xdm slim; do
        if dpkg-query -W -f='${Status}' "$dm" 2>/dev/null | grep -q 'install ok installed'; then
            PROFILE=workstation; PROFILE_WHY="$dm instalado"; return
        fi
    done
    PROFILE=server; PROFILE_WHY="sin entorno gráfico"
}

# Registro de riesgos aceptados. Formato por línea:  ID  motivo de la aceptación
load_exceptions() {
    local f=$1 id just n=0
    [[ -r "$f" ]] || die "no se puede leer el archivo de excepciones: $f"
    # Si un usuario sin privilegios pudiera editarlo, podría ocultar hallazgos
    # (por ejemplo, su propia puerta trasera). Como root, solo se acepta un
    # archivo de root que nadie más pueda modificar.
    if [[ $IS_ROOT -eq 1 && -n "$(find "$f" -maxdepth 0 \( ! -user root -o -perm /022 \) 2>/dev/null)" ]]; then
        EXC_WARN="$f no pertenece a root o es modificable por otros: se ignoró"
        return
    fi
    while read -r id just; do
        [[ -z "$id" || "$id" == \#* ]] && continue
        if [[ "$id" =~ ^[A-Z]+-[0-9]+$ ]]; then
            EXC[$id]=${just:-sin motivo documentado}; n=$((n + 1))
        fi
    done < "$f"
    EXC_FILE="$f ($n)"
}

list_checks() {
    local id lv bench desc
    printf '| ID | Servidor | Estación | Referencia | Qué verifica |\n|----|----|----|----|----|\n'
    local order="SYS UPD ACC SSH FS KRN NET LOG SVC MAC BOOT CNT"
    for id in "${!META[@]}"; do
        local c=${id%%-*} rank=0 k=0 x
        for x in $order; do k=$((k + 1)); [[ $x == "$c" ]] && rank=$k; done
        printf '%02d\t%s\n' "$rank" "$id"
    done | sort -t- -k1,1 -k2,2n | cut -f2 \
      | while IFS= read -r id; do
            IFS='|' read -r lv bench desc <<< "${META[$id]}"
            local s=${lv:0:1} w=${lv:1:1}
            [[ $s == X ]] && s="Extra" || s="N$s"
            [[ $w == X ]] && w="Extra" || w="N$w"
            [[ $lv == XX ]] || bench="CIS §$bench"
            printf '| %s | %s | %s | %s | %s |\n' "$id" "$s" "$w" "$bench" "$desc"
        done
}

# =============================================================================
#  Registro de resultados
# =============================================================================
# record ID ESTADO SEVERIDAD "Título" "Detalle" "Solución" "Referencias"
#   ESTADO: PASS | WARN | FAIL | INFO | SKIP
#   SEVERIDAD: critical | high | medium | low | none
#
# Aquí se aplican, en un solo lugar, las reglas que hacen el informe justo:
#   1. Riesgo latente: si SSH está apagado, sus hallazgos bajan a BAJO.
#   2. Nivel CIS: con --level 1, un control de nivel 2 de riesgo medio o bajo
#      pasa a ser una RECOMENDACIÓN (estado L2) y no resta puntos. Si el riesgo
#      es alto o crítico se mantiene, porque el impacto real lo justifica.
#   3. Excepciones: un riesgo aceptado y documentado pasa a ACEPTADO.
record() {
    local id=$1 status=$2 sev=$3 title=$4 detail=${5:-} fix=${6:-} ref=${7:-}
    local cat=${id%%-*} lv bench eff lvtxt
    IFS='|' read -r lv bench _ <<< "${META[$id]:-XX||}"
    if [[ "$PROFILE" == workstation ]]; then eff=${lv:1:1}; else eff=${lv:0:1}; fi
    local active=0; [[ "$status" == FAIL || "$status" == WARN ]] && active=1

    if [[ $active -eq 1 && "$cat" == SSH && $SSH_LATENT -eq 1 && $(sev_num "$sev") -gt 1 ]]; then
        sev=low
        detail="SSH está apagado: riesgo latente, importa si lo enciendes. $detail"
    fi
    if [[ $active -eq 1 && "$eff" == 2 && $LEVEL -eq 1 ]]; then
        if [[ $(sev_num "$sev") -le 2 ]]; then
            status=L2
        else
            detail="El CIS lo clasifica como Nivel 2, pero aquí el riesgo es alto. $detail"
        fi
    fi
    if [[ -n "${EXC[$id]:-}" && "$status" =~ ^(FAIL|WARN|L2)$ ]]; then
        status=ACCEPT
        detail="Riesgo aceptado: ${EXC[$id]}. Hallazgo original: $title. $detail"
    fi

    case "$eff" in
        1|2) lvtxt="CIS N$eff"; ref="CIS Ubuntu 24.04 §$bench${ref:+ · $ref}" ;;
        *)   lvtxt="Extra"; [[ -n "$bench" ]] && ref="${ref:+$ref · }$bench" ;;
    esac

    R_ID+=("$id"); R_CAT+=("$cat"); R_STATUS+=("$status"); R_SEV+=("$sev")
    R_TITLE+=("$title"); R_DETAIL+=("$detail"); R_FIX+=("$fix"); R_REF+=("$ref"); R_LVL+=("$lvtxt")
    live_print "${#R_ID[@]}"
}

# =============================================================================
#  Salida en vivo (terminal)
# =============================================================================
LIVE=1

setup_colors() {
    if [[ $USE_COLOR -eq 1 ]]; then
        C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'
        C_MAG=$'\e[35m'; C_GRY=$'\e[90m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
    else
        C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_GRY=""; C_BLD=""; C_RST=""
    fi
}

format_line() {
    # Imprime un hallazgo en texto. $1 = índice (0..n-1). $2 = 1 para color.
    local i=$1 color=$2
    local st=${R_STATUS[$i]} sev=${R_SEV[$i]}
    local tag c=""
    tag="[$(status_label "$st")]"
    if [[ $color -eq 1 ]]; then
        case "$st" in
            PASS) c=$C_GRN ;; WARN) c=$C_YEL ;; FAIL) c=$C_RED ;; L2|ACCEPT) c=$C_BLU ;; *) c=$C_GRY ;;
        esac
        [[ "$st" == FAIL && "$sev" == critical ]] && c=$C_MAG
    fi
    local sevtxt=""
    if [[ "$st" == FAIL || "$st" == WARN ]]; then
        sevtxt=" ($(sev_label "$sev"))"
    elif [[ "$st" == L2 ]]; then
        sevtxt=" (opcional)"
    fi
    local rst=""; [[ $color -eq 1 ]] && rst=$C_RST
    local gry=""; [[ $color -eq 1 ]] && gry=$C_GRY
    printf '  %s%-10s%s %-8s %s%s\n' "$c" "$tag" "$rst" "${R_ID[$i]}" "${R_TITLE[$i]}" "$sevtxt"
    if [[ -n "${R_DETAIL[$i]}" ]]; then
        printf '  %s%-10s %-8s %s%s\n' "$gry" "" "" "${R_DETAIL[$i]}" "$rst"
    fi
    if [[ "$st" =~ ^(FAIL|WARN|L2)$ && -n "${R_FIX[$i]}" ]]; then
        printf '  %-10s %-8s → %s\n' "" "" "${R_FIX[$i]}"
    fi
}

live_print() {
    [[ $LIVE -eq 1 ]] || return 0
    local i=$(( $1 - 1 ))
    local st=${R_STATUS[$i]}
    if [[ $QUIET -eq 1 && "$st" != FAIL && "$st" != WARN ]]; then
        return 0
    fi
    if [[ "${R_CAT[$i]}" != "$LAST_CAT" ]]; then
        LAST_CAT=${R_CAT[$i]}
        printf '\n%s== %s ==%s\n' "${C_BLD}${C_BLU}" "$(cat_label "$LAST_CAT")" "$C_RST"
    fi
    format_line "$i" "$USE_COLOR"
}

# =============================================================================
#  PRUEBAS — SISTEMA
# =============================================================================
check_sys() {
    record SYS-001 INFO none "Equipo auditado" \
        "$(hostname 2>/dev/null) · $(os_name) · kernel $(uname -r)"
    if [[ $IS_ROOT -eq 1 ]]; then
        record SYS-002 INFO none "Ejecución como root: auditoría completa"
    else
        record SYS-002 INFO none "Ejecución sin root: varias pruebas se omitirán" \
            "Para una auditoría completa usa: sudo $0"
    fi
    local pl="Servidor"; [[ "$PROFILE" == workstation ]] && pl="Estación de trabajo"
    record SYS-003 INFO none "Perfil: $pl ($PROFILE_WHY) · Nivel CIS exigido: $LEVEL" \
        "Excepciones: ${EXC_FILE:-ninguna}. Cambia el perfil con --profile y el nivel con --level."
    if [[ -n "$EXC_WARN" ]]; then
        record SYS-004 FAIL high "Archivo de excepciones inseguro" "$EXC_WARN" \
            "sudo chown root:root ARCHIVO && sudo chmod 644 ARCHIVO" "MITRE T1562"
    fi
}

# =============================================================================
#  PRUEBAS — ACTUALIZACIONES  (CIS Control 7: gestión continua de vulnerabilidades)
# =============================================================================
check_upd() {
    local ref="CIS v8 7.3, 7.4"
    if ! have apt-get; then
        record UPD-001 SKIP none "Actualizaciones: sistema sin apt (no soportado aún)"
        return
    fi

    # UPD-001 Antigüedad de la lista de paquetes
    local newest age_days
    newest=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*Packages*' -printf '%T@\n' 2>/dev/null \
             | sort -n | tail -n1 | cut -d. -f1)
    if [[ -z "$newest" ]]; then
        record UPD-001 WARN low "La lista de paquetes nunca se ha descargado" \
            "No se puede saber qué actualizaciones faltan." \
            "sudo apt update" "$ref"
    else
        age_days=$(( ( $(date +%s) - newest ) / 86400 ))
        if [[ $age_days -gt 7 ]]; then
            record UPD-001 WARN low "Lista de paquetes desactualizada ($age_days días)" \
                "El conteo de actualizaciones de UPD-002 puede quedarse corto." \
                "sudo apt update" "$ref"
        else
            record UPD-001 PASS low "Lista de paquetes reciente ($age_days días)" "" "" "$ref"
        fi
    fi

    # UPD-002 Actualizaciones pendientes (simulación: no cambia nada)
    local sim total sec
    sim=$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null | grep '^Inst ' || true)
    total=$(grep -c . <<< "$sim" || true)
    # Solo cuenta como "de seguridad" si el ORIGEN del paquete (lo que va entre
    # paréntesis) es un repositorio de seguridad, ej. "(1.2 Debian-Security:12/...)".
    # Buscar la palabra en toda la línea daba falsos positivos con paquetes como
    # "libfalcosecurity0t64".
    local sec_lines
    sec_lines=$(grep -iE '\([^)]*security' <<< "$sim" || true)
    sec=$(grep -c . <<< "$sec_lines" || true)
    if [[ $sec -gt 0 ]]; then
        record UPD-002 FAIL high "$sec actualizaciones de SEGURIDAD pendientes ($total en total)" \
            "Paquetes: $(awk '{print $2}' <<< "$sec_lines" | join_list 8)" \
            "sudo apt update && sudo apt full-upgrade" "$ref · MITRE T1190, T1068"
    elif [[ $total -ge 50 ]]; then
        record UPD-002 FAIL high "$total actualizaciones pendientes: el sistema lleva tiempo sin actualizarse" \
            "Con tantas pendientes es casi seguro que hay vulnerabilidades conocidas sin parchear. En Kali y otras distribuciones 'rolling' no se separan las de seguridad." \
            "sudo apt update && sudo apt full-upgrade" "$ref · MITRE T1190, T1068"
    elif [[ $total -gt 0 ]]; then
        record UPD-002 FAIL medium "$total actualizaciones pendientes" \
            "En distribuciones 'rolling' como Kali no se separan las de seguridad: trátalas todas como importantes." \
            "sudo apt update && sudo apt full-upgrade" "$ref · MITRE T1068"
    else
        record UPD-002 PASS high "Sin actualizaciones pendientes" "" "" "$ref"
    fi

    # UPD-003 Actualizaciones automáticas. En distribuciones rolling (Kali) no
    # se recomiendan: una actualización desatendida puede romper el sistema.
    local osid
    osid=$(sed -n 's/^ID=["'\'']\{0,1\}\([^"'\'']*\).*/\1/p' /etc/os-release 2>/dev/null | head -n1)
    if [[ "$osid" == kali ]]; then
        record UPD-003 INFO none "Kali es una distribución rolling: actualiza manualmente con frecuencia" \
            "Las actualizaciones automáticas no se recomiendan en rolling: un cambio grande podría romper el sistema sin que estés presente." \
            "" "$ref"
    elif dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
        record UPD-003 PASS medium "unattended-upgrades instalado" "" "" "$ref"
    else
        record UPD-003 WARN medium "Sin actualizaciones automáticas de seguridad" \
            "En servidores es la forma más simple de cerrar vulnerabilidades a tiempo." \
            "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades" "$ref"
    fi

    # UPD-004 Reinicio pendiente (kernel o librerías parcheadas sin cargar)
    if [[ -f /var/run/reboot-required ]]; then
        record UPD-004 WARN medium "Reinicio pendiente para aplicar parches" \
            "$( { join_list 6 < /var/run/reboot-required.pkgs; } 2>/dev/null )" \
            "Programa un reinicio: sudo reboot" "$ref"
    else
        record UPD-004 PASS medium "No hay reinicio pendiente" "" "" "$ref"
    fi
}

# =============================================================================
#  PRUEBAS — CUENTAS  (CIS Control 5 y 6)
# =============================================================================
check_acc() {
    # ACC-001 Cuentas con UID 0 además de root
    local uid0
    uid0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    if [[ -n "$uid0" ]]; then
        record ACC-001 FAIL critical "Cuentas con UID 0 además de root" \
            "Cuentas: $(join_list <<< "$uid0"). Patrón típico de puerta trasera." \
            "Trátalo como incidente: bloquéala (sudo usermod -L -e 1 -s /usr/sbin/nologin CUENTA), conserva evidencia (last, journalctl) y luego investiga" \
            "CIS v8 5.4 · MITRE T1136.001"
    else
        record ACC-001 PASS critical "Solo 'root' tiene UID 0" "" "" "CIS v8 5.4"
    fi

    # ACC-002 Nombres o UID duplicados
    local dup_uid dup_name
    dup_uid=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    dup_name=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
    if [[ -n "$dup_uid$dup_name" ]]; then
        record ACC-002 FAIL high "UID o nombres de usuario duplicados" \
            "UID: ${dup_uid//$'\n'/ } Nombres: ${dup_name//$'\n'/ }" \
            "Asigna un UID único a cada cuenta (usermod -u)" "CIS v8 5.1"
    else
        record ACC-002 PASS high "Sin UID ni nombres duplicados" "" "" "CIS v8 5.1"
    fi

    # ACC-003 / ACC-004 requieren leer /etc/shadow
    if [[ $IS_ROOT -eq 1 && -r /etc/shadow ]]; then
        local empty
        empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
        if [[ -n "$empty" ]]; then
            record ACC-003 FAIL critical "Cuentas sin contraseña" \
                "Cuentas: $(join_list <<< "$empty")" \
                "Bloquéalas: sudo passwd -l CUENTA" "CIS v8 5.2 · MITRE T1078"
        else
            record ACC-003 PASS critical "Ninguna cuenta tiene contraseña vacía" "" "" "CIS v8 5.2"
        fi

        # Algoritmos de hash obsoletos. Nunca mostramos los hashes, solo cuentas.
        local weak
        weak=$(awk -F: '
            $2 ~ /^[!*]/ || $2 == "" { next }
            $2 ~ /^\$1\$/ { print $1 " (MD5)"; next }
            $2 !~ /^\$/   { print $1 " (DES)" }' /etc/shadow)
        if [[ -n "$weak" ]]; then
            record ACC-004 FAIL high "Contraseñas guardadas con algoritmos rotos" \
                "$(join_list <<< "$weak"). Se crackean en minutos si roban /etc/shadow." \
                "Cambia esas contraseñas (passwd) tras configurar yescrypt o SHA512" \
                "CIS v8 3.11 · MITRE T1110.002"
        else
            record ACC-004 PASS high "Hashes de contraseña con algoritmos modernos" "" "" "CIS v8 3.11"
        fi
    else
        record ACC-003 SKIP none "Contraseñas vacías: requiere root"
        record ACC-004 SKIP none "Algoritmo de hash: requiere root"
    fi

    # ACC-005 Algoritmo configurado para contraseñas nuevas
    local enc
    enc=$(conf_get /etc/login.defs ENCRYPT_METHOD)
    case "${enc^^}" in
        YESCRYPT|SHA512|"")
            record ACC-005 PASS medium "Algoritmo para contraseñas nuevas: ${enc:-yescrypt (PAM)}" "" "" "CIS v8 3.11" ;;
        *)
            record ACC-005 FAIL medium "Algoritmo débil para contraseñas nuevas: $enc" "" \
                "En /etc/login.defs: ENCRYPT_METHOD YESCRYPT" "CIS v8 3.11" ;;
    esac

    # ACC-006 Longitud mínima de contraseña
    local minlen
    minlen=$(conf_get /etc/security/pwquality.conf minlen)
    if [[ -z "$minlen" ]] && ls /etc/security/pwquality.conf.d/*.conf >/dev/null 2>&1; then
        minlen=$(cat /etc/security/pwquality.conf.d/*.conf 2>/dev/null \
                 | awk '/^[[:space:]]*minlen/ {sub(/=/," "); v=$2} END {print v}')
    fi
    if [[ -n "$minlen" && "$minlen" -ge 14 ]]; then
        record ACC-006 PASS medium "Longitud mínima de contraseña: $minlen" "" "" "CIS v8 5.2"
    else
        record ACC-006 WARN medium "Longitud mínima de contraseña no exigida o < 14 (actual: ${minlen:-sin definir})" \
            "Las contraseñas cortas caen ante fuerza bruta." \
            "sudo apt install libpam-pwquality y en /etc/security/pwquality.conf: minlen = 14" \
            "CIS v8 5.2 · NIST 800-63B"
    fi

    # ACC-007 Caducidad de contraseñas (CIS la pide; NIST 800-63B ya no la recomienda)
    local maxdays
    maxdays=$(conf_get /etc/login.defs PASS_MAX_DAYS)
    if [[ -n "$maxdays" && "$maxdays" -le 365 ]]; then
        record ACC-007 PASS low "Caducidad de contraseñas: $maxdays días" "" "" "CIS v8 5.2"
    else
        record ACC-007 WARN low "Las contraseñas no caducan (PASS_MAX_DAYS=${maxdays:-sin definir})" \
            "CIS exige ≤365 días; NIST 800-63B prefiere no forzar cambios. Sigue la política de tu empresa." \
            "En /etc/login.defs: PASS_MAX_DAYS 365" "CIS v8 5.2"
    fi

    # ACC-008 Cuentas del sistema con shell interactiva (CIS 5.4.2.7).
    # Contexto justo: si la contraseña está bloqueada, nadie puede entrar con
    # ella; el riesgo real es mucho menor (solo vía su/sudo desde root).
    local sysshell acct pw open_accts="" locked_accts=""
    sysshell=$(awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7 != "" {print $1}' /etc/passwd)
    while IFS= read -r acct; do
        [[ -z "$acct" ]] && continue
        local why=""
        case "$acct" in
            postgres) why=" — el paquete postgresql la crea así para administrar la base con 'sudo -u postgres psql'" ;;
        esac
        pw=""
        [[ $IS_ROOT -eq 1 ]] && pw=$(awk -F: -v u="$acct" '$1 == u {print $2}' /etc/shadow 2>/dev/null)
        if [[ "$pw" == [\!\*]* ]]; then
            locked_accts+="$acct (contraseña bloqueada$why)"$'\n'
        else
            open_accts+="$acct${why:+ ($why)}"$'\n'
        fi
    done <<< "$sysshell"
    if [[ -n "$open_accts" ]]; then
        record ACC-008 WARN medium "Cuentas de servicio con shell interactiva" \
            "$(join_list <<< "$open_accts$locked_accts")" \
            "Si no necesitan login: sudo usermod -s /usr/sbin/nologin CUENTA" \
            "CIS v8 5.3 · MITRE T1078.003"
    elif [[ -n "$locked_accts" ]]; then
        record ACC-008 WARN low "Cuentas de servicio con shell pero sin poder iniciar sesión con contraseña" \
            "$(join_list <<< "$locked_accts")" \
            "Riesgo bajo. Para cumplir CIS: sudo usermod -s /usr/sbin/nologin CUENTA (comprueba antes que el servicio no la necesite)" \
            "CIS v8 5.3"
    else
        record ACC-008 PASS medium "Cuentas de servicio sin shell interactiva" "" "" "CIS v8 5.3"
    fi

    # ACC-009 / ACC-010 sudo
    if [[ $IS_ROOT -eq 1 ]]; then
        # Cada regla NOPASSWD se clasifica según su riesgo REAL:
        #   - ¿Alguien puede usarla? Una regla para un %grupo sin miembros no
        #     afecta a nadie hoy (ej. %kali-trusted en Kali).
        #   - ¿Permite TODO (ALL) o solo un comando concreto?
        local nopass line who cmds grp gid members
        local active_all="" active_limited="" inactive=""
        nopass=$(grep -rsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
                 | sed 's/[[:space:]]\+/ /g')
        local src pkg ctx
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            src=${line%%:*}; line=${line#*:}; line=${line# }
            who=${line%% *}
            # Los comandos se leen ANTES de añadir el contexto a la línea
            cmds=${line#*NOPASSWD:}; cmds=${cmds# }
            # ¿Para qué existe esta regla? Lo dice el paquete que la instaló.
            # /etc/sudoers pertenece al paquete sudo, pero sus reglas extra las
            # escribe un administrador: solo se atribuyen los archivos de sudoers.d
            pkg=""; [[ "$src" != /etc/sudoers ]] && pkg=$(pkg_of "$src")
            case "$who" in
                _gvm)            ctx="necesaria para OpenVAS/GVM" ;;
                %kali-trusted)   ctx="de kali-grant-root: solo afecta a quien agregues al grupo" ;;
                vagrant|ec2-user) ctx="habitual en máquinas Vagrant/AWS; CIS permite excluirla" ;;
                *)               ctx="" ;;
            esac
            [[ -n "$pkg" ]] && ctx="${ctx:+$ctx; }instalada por el paquete $pkg"
            if [[ "$src" == /etc/sudoers ]]; then
                ctx="${ctx:+$ctx; }en el archivo principal, editado por un administrador"
            elif [[ -z "$pkg" && -n "$ctx" ]]; then
                ctx="$ctx; no registrada por apt (la suele crear el instalador de la herramienta)"
            elif [[ -z "$pkg" ]]; then
                ctx="no registrada por ningún paquete: confirma quién la agregó y por qué"
            fi
            line+=" [${src}${ctx:+ — $ctx}]"
            if [[ "$who" == %* ]]; then
                grp=${who#%}
                members=$(getent group "$grp" 2>/dev/null | cut -d: -f4)
                gid=$(getent group "$grp" 2>/dev/null | cut -d: -f3)
                # También cuentan los usuarios que tienen ese grupo como principal
                if [[ -n "$gid" ]]; then
                    members+=$(awk -F: -v g="$gid" '$4 == g {printf ",%s", $1}' /etc/passwd)
                fi
                if [[ -z "${members//,/}" ]]; then
                    inactive+="$line (grupo sin miembros)"$'\n'
                    continue
                fi
                line+=" [miembros: ${members#,}]"
            fi
            # "ALL" como comando (o la lista contiene ALL) = root completo
            if [[ ",${cmds// /}," == *",ALL,"* ]]; then
                active_all+="$line"$'\n'
            else
                active_limited+="$line"$'\n'
            fi
        done <<< "$nopass"

        local ref009="CIS v8 5.4, 6.1 · MITRE T1548.003"
        if [[ -n "$active_all" ]]; then
            record ACC-009 FAIL high "Usuarios que pueden ser root sin contraseña (NOPASSWD: ALL)" \
                "$(join_list 5 <<< "$active_all"). Quien robe esa sesión es root al instante." \
                "Elimina NOPASSWD con: sudo visudo (y revisa /etc/sudoers.d/)" "$ref009"
        elif [[ -n "$active_limited" ]]; then
            record ACC-009 WARN medium "Reglas sudo sin contraseña limitadas a comandos concretos" \
                "$(join_list 5 <<< "$active_limited"). Revisa que esos programas no permitan abrir una shell (ver GTFOBins).${inactive:+ Además, sin usuarios hoy: $(join_list 5 <<< "$inactive").}" \
                "Si no son necesarias, elimínalas con: sudo visudo" "$ref009"
        elif [[ -n "$inactive" ]]; then
            record ACC-009 WARN low "Reglas NOPASSWD sin usuarios afectados hoy" \
                "$(join_list 5 <<< "$inactive"). Si alguien entra a ese grupo, será root sin contraseña." \
                "Elimínalas si no las usas, o documéntalas como riesgo aceptado" "$ref009"
        else
            record ACC-009 PASS high "sudo siempre pide contraseña" "" "" "CIS v8 5.4"
        fi
        # Las reglas limitadas también se informan aunque haya una ALL
        if [[ -n "$active_all" && -n "$active_limited$inactive" ]]; then
            record ACC-013 INFO none "Otras reglas NOPASSWD (limitadas o sin miembros)" \
                "$(join_list 5 <<< "$active_limited$inactive")" "" "$ref009"
        fi

        local badsudo
        badsudo=$(find /etc/sudoers /etc/sudoers.d -maxdepth 1 -type f \( -perm /022 -o ! -user root \) 2>/dev/null)
        if [[ -n "$badsudo" ]]; then
            record ACC-010 FAIL critical "Archivos sudoers modificables por otros usuarios" \
                "$(join_list <<< "$badsudo")" \
                "sudo chown root:root ARCHIVO && sudo chmod 440 ARCHIVO" "CIS v8 4.1 · MITRE T1548.003"
        else
            record ACC-010 PASS critical "Archivos sudoers protegidos" "" "" "CIS v8 4.1"
        fi
    else
        record ACC-009 SKIP none "Reglas NOPASSWD: requiere root"
        record ACC-010 SKIP none "Permisos de sudoers: requiere root"
    fi

    # ACC-011 Usuarios con privilegios de administración (inventario)
    local admins=""
    local g
    for g in sudo wheel admin; do
        getent group "$g" >/dev/null 2>&1 && admins+="$(getent group "$g" | cut -d: -f4),"
    done
    admins=$(tr ',' '\n' <<< "$admins" | sort -u | join_list)
    record ACC-011 INFO none "Usuarios con sudo" "${admins:-ninguno}" "" "CIS v8 5.4"

    # ACC-012 umask por defecto
    local um
    um=$(conf_get /etc/login.defs UMASK)
    if [[ -n "$um" && $(( 8#$um & 8#027 )) -eq $(( 8#027 )) ]]; then
        record ACC-012 PASS low "umask por defecto restrictiva ($um)" "" "" "CIS v8 3.3"
    else
        record ACC-012 WARN low "umask por defecto permisiva (${um:-no definida en login.defs, se usa 022})" \
            "Los archivos nuevos pueden quedar legibles por otros usuarios." \
            "En /etc/login.defs: UMASK 027" "CIS v8 3.3"
    fi

    # ACC-014 Bloqueo tras intentos fallidos (CIS 5.3.2.2): sin esto, un atacante
    # local o por SSH puede probar contraseñas sin límite.
    local pamfile=""
    for pamfile in /etc/pam.d/common-auth /etc/pam.d/system-auth; do [[ -r "$pamfile" ]] && break; pamfile=""; done
    if [[ -z "$pamfile" ]]; then
        record ACC-014 SKIP none "Bloqueo por intentos fallidos: configuración PAM no encontrada"
    elif grep -qE '^[[:space:]]*auth[[:space:]].*pam_faillock\.so' "$pamfile"; then
        record ACC-014 PASS medium "pam_faillock bloquea cuentas tras intentos fallidos" "" "" "CIS v8 5.2"
    else
        record ACC-014 WARN medium "Las cuentas no se bloquean tras intentos fallidos" \
            "Sin pam_faillock se pueden probar contraseñas sin límite (consola, su, SSH con PAM)." \
            "Activa pam_faillock (CIS: deny de 5 o menos, unlock_time=900) con un perfil de pam-auth-update; prueba antes en una sesión aparte para no quedarte fuera" \
            "CIS v8 5.2 · MITRE T1110.001"
    fi

    # ACC-015 sudo deja rastro: use_pty (CIS 5.2.2) y log propio (CIS 5.2.3)
    if have sudo && [[ $IS_ROOT -eq 1 ]]; then
        local sdef ver pty=0 slog=0
        sdef=$(grep -rhsE '^[[:space:]]*Defaults' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
        grep -qE '(^|[ ,])use_pty' <<< "$sdef" && pty=1
        grep -qE '(^|[ ,])logfile[[:space:]]*=' <<< "$sdef" && slog=1
        # Desde sudo 1.9.14, use_pty viene activado por defecto
        ver=$(sudo -V 2>/dev/null | awk 'NR==1 {print $3}')
        if [[ $pty -eq 0 && -n "$ver" && "$(printf '%s\n1.9.14\n' "${ver%%p*}" | sort -V | head -n1)" == 1.9.14 ]]; then
            pty=1
        fi
        local miss=""
        [[ $pty -eq 0 ]] && miss+="use_pty "
        [[ $slog -eq 0 ]] && miss+="logfile "
        if [[ -z "$miss" ]]; then
            record ACC-015 PASS low "sudo usa pty y registra en su propio log" "" "" "CIS v8 8.2"
        else
            record ACC-015 WARN low "sudo sin: ${miss% }" \
                "use_pty impide que un programa ejecutado con sudo siga corriendo a escondidas; logfile deja un registro aparte de quién usó sudo." \
                "sudo visudo -f /etc/sudoers.d/60-linux-audit  y agrega: Defaults use_pty  y  Defaults logfile=\"/var/log/sudo.log\"" \
                "CIS v8 8.2"
        fi
    else
        record ACC-015 SKIP none "Configuración de sudo: requiere root"
    fi

    # ACC-016 Grupo shadow vacío (CIS 7.2.4): sus miembros leen todos los hashes
    local shmembers="" shgid
    if getent group shadow >/dev/null 2>&1; then
        shmembers=$(getent group shadow | cut -d: -f4)
        shgid=$(getent group shadow | cut -d: -f3)
        shmembers+=$(awk -F: -v g="$shgid" '$4 == g {printf ",%s", $1}' /etc/passwd)
        shmembers=${shmembers#,}
        if [[ -n "${shmembers//,/}" ]]; then
            record ACC-016 FAIL high "Usuarios en el grupo shadow: ${shmembers//,/, }" \
                "Pueden leer /etc/shadow y crackear las contraseñas de todos sin conexión." \
                "sudo gpasswd -d USUARIO shadow" "CIS v8 5.4 · MITRE T1003.008"
        else
            record ACC-016 PASS high "El grupo shadow no tiene miembros" "" "" "CIS v8 5.4"
        fi
    fi
}

# =============================================================================
#  PRUEBAS — SSH  (CIS Control 4, 5, 12)
# =============================================================================
check_ssh() {
    if ! have sshd && [[ ! -f /etc/ssh/sshd_config ]]; then
        record SSH-001 PASS high "Servidor SSH no instalado (menos superficie de ataque)"
        return
    fi

    # ¿Está SSH en uso? Si está apagado y no arranca solo, sus fallos de
    # configuración son un riesgo LATENTE: no se pueden explotar hoy.
    # (Ubuntu 24.04 activa SSH por socket, por eso también se mira ssh.socket.)
    SSH_LATENT=0
    if have systemctl && systemctl list-units --no-pager >/dev/null 2>&1; then
        local u inuse=0
        for u in ssh sshd ssh.socket; do
            systemctl is-active --quiet "$u" 2>/dev/null && inuse=1
            systemctl is-enabled --quiet "$u" 2>/dev/null && inuse=1
        done
        if [[ $inuse -eq 0 ]]; then
            SSH_LATENT=1
            record SSH-000 INFO none "SSH instalado pero apagado y sin arranque automático" \
                "Sus hallazgos se marcan como BAJO (riesgo latente). Si no lo usas, puedes desinstalarlo: sudo apt purge openssh-server"
        else
            record SSH-000 INFO none "SSH en uso (activo o con arranque automático)"
        fi
    fi

    # Configuración EFECTIVA con 'sshd -T' (incluye sshd_config.d/ y valores
    # por defecto). Sin root leemos el archivo (menos preciso).
    local cfg="" effective=0
    # Nota: si SSH nunca se ha iniciado, falta /run/sshd y 'sshd -T' falla;
    # NO lo creamos (el script jamás modifica el sistema) y usamos el archivo.
    if [[ $IS_ROOT -eq 1 ]] && have sshd; then
        cfg=$(sshd -T 2>/dev/null) && [[ -n "$cfg" ]] && effective=1
    fi
    if [[ $effective -eq 0 ]]; then
        cfg=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
              | grep -Ev '^[[:space:]]*(#|$)' | tr '[:upper:]' '[:lower:]')
    fi
    # Primera aparición gana (así funciona sshd)
    ssh_opt() { awk -v k="$1" 'tolower($1) == k { $1=""; sub(/^ /, ""); print tolower($0); exit }' <<< "$cfg"; }

    local v
    local pwauth
    pwauth=$(ssh_opt passwordauthentication); pwauth=${pwauth:-yes}
    v=$(ssh_opt permitrootlogin); v=${v:-prohibit-password}
    # Con llave no hay fuerza bruta posible: el riesgo es de trazabilidad
    # (no queda registro de qué persona entró como root), no de intrusión.
    [[ "$v" == yes && "$pwauth" == no ]] && v="yes (solo con llave)"
    case "$v" in
        no) record SSH-001 PASS high "PermitRootLogin no" "" "" "CIS v8 5.4" ;;
        prohibit-password|without-password|forced-commands-only|"yes (solo con llave)")
            record SSH-001 WARN medium "root puede entrar por SSH con llave (PermitRootLogin $v)" \
                "No permite fuerza bruta, pero no queda registro de qué persona entró como root. Mejor: entrar con usuario propio y usar sudo." \
                "En sshd_config: PermitRootLogin no" "CIS v8 5.4 · MITRE T1078.003" ;;
        *)  record SSH-001 FAIL high "root puede entrar por SSH con contraseña (PermitRootLogin $v)" \
                "Es el primer usuario que prueban los bots de fuerza bruta." \
                "En sshd_config: PermitRootLogin no" "CIS v8 5.4 · MITRE T1110" ;;
    esac

    if [[ "$pwauth" == no ]]; then
        record SSH-002 PASS medium "Solo autenticación por llave (PasswordAuthentication no)" "" "" "CIS v8 6.5"
    else
        record SSH-002 WARN medium "SSH acepta contraseñas (PasswordAuthentication $pwauth)" \
            "El CIS no lo exige, pero guías como la de Mozilla lo recomiendan y es práctica habitual: las contraseñas se pueden adivinar o filtrar; las llaves no." \
            "Configura llaves (ssh-copy-id) y luego: PasswordAuthentication no" \
            "CIS v8 6.5 · MITRE T1110"
    fi

    v=$(ssh_opt permitemptypasswords)
    if [[ "${v:-no}" == no ]]; then
        record SSH-003 PASS critical "PermitEmptyPasswords no" "" "" "CIS v8 5.2"
    else
        record SSH-003 FAIL critical "SSH permite contraseñas vacías" "" \
            "En sshd_config: PermitEmptyPasswords no" "CIS v8 5.2 · MITRE T1078"
    fi

    v=$(ssh_opt maxauthtries)
    if [[ -n "$v" && "$v" -le 4 ]]; then
        record SSH-004 PASS low "MaxAuthTries $v" "" "" "CIS v8 4.1"
    else
        record SSH-004 FAIL low "MaxAuthTries ${v:-6} (recomendado ≤ 4)" "" \
            "En sshd_config: MaxAuthTries 4" "CIS v8 4.1 · MITRE T1110"
    fi

    # CIS 5.1.8: DisableForwarding yes desactiva de una vez el reenvío X11,
    # de agente y de puertos TCP (usados para pivotar dentro de la red).
    v=$(ssh_opt disableforwarding)
    if [[ "$v" == yes ]]; then
        record SSH-005 PASS low "DisableForwarding yes" "" "" "CIS v8 4.8"
    else
        local fw=""
        [[ "$(ssh_opt x11forwarding)" == yes ]] && fw+="X11 "
        [[ "$(ssh_opt allowtcpforwarding)" != no ]] && fw+="TCP "
        [[ "$(ssh_opt allowagentforwarding)" != no ]] && fw+="agente "
        record SSH-005 FAIL low "Reenvío por SSH permitido (${fw% })" \
            "Un usuario con acceso SSH puede usar este equipo como puente hacia otros de la red." \
            "En sshd_config: DisableForwarding yes (si necesitas túneles, usa Match para limitarlo)" \
            "CIS v8 4.8 · MITRE T1572"
    fi

    # SSH-006 Criptografía débil (solo es fiable con la configuración efectiva)
    if [[ $effective -eq 1 ]]; then
        local weak=""
        # Listas de algoritmos débiles según CIS (5.1.6, 5.1.12, 5.1.15).
        # Nota: CIS NO considera débil hmac-sha1 (sí umac-64, MD5, RIPEMD160 y
        # los de 96 bits); otras herramientas como ssh-audit son más estrictas.
        weak+=$(ssh_opt ciphers | tr ',' '\n' | grep -E 'cbc|arcfour|3des|blowfish|cast128|rijndael' | sed 's/^/cipher:/')$'\n'
        weak+=$(ssh_opt macs | tr ',' '\n' | grep -E 'md5|-96|ripemd160|umac-64' | sed 's/^/mac:/')$'\n'
        weak+=$(ssh_opt kexalgorithms | tr ',' '\n' | grep -E 'group1-sha1|group14-sha1|group-exchange-sha1' | sed 's/^/kex:/')
        weak=$(grep . <<< "$weak" || true)
        if [[ -n "$weak" ]]; then
            record SSH-006 FAIL medium "Algoritmos criptográficos débiles habilitados en SSH" \
                "$(join_list 6 <<< "$weak")" \
                "Ejemplo CIS: MACs -umac-64@openssh.com,umac-64-etm@openssh.com,hmac-md5,hmac-md5-96,hmac-sha1-96 (el '-' los quita de la lista por defecto)" \
                "CIS v8 3.10 · MITRE T1557"
        else
            record SSH-006 PASS medium "Sin algoritmos criptográficos débiles en SSH" "" "" "CIS v8 3.10"
        fi
    else
        record SSH-006 SKIP none "Criptografía SSH: requiere root (sshd -T)"
    fi

    v=$(ssh_opt permituserenvironment)
    if [[ "${v:-no}" == no ]]; then
        record SSH-007 PASS medium "PermitUserEnvironment no" "" "" "CIS v8 4.1"
    else
        record SSH-007 FAIL medium "PermitUserEnvironment activo" \
            "Un usuario podría cargar variables que alteran programas (LD_PRELOAD)." \
            "En sshd_config: PermitUserEnvironment no" "CIS v8 4.1 · MITRE T1574.006"
    fi

    local hb ir
    hb=$(ssh_opt hostbasedauthentication); ir=$(ssh_opt ignorerhosts)
    if [[ "${hb:-no}" == no && "${ir:-yes}" == yes ]]; then
        record SSH-008 PASS medium "Autenticación por host (rhosts) deshabilitada" "" "" "CIS v8 4.8"
    else
        record SSH-008 FAIL medium "Autenticación por host/rhosts habilitada" "" \
            "En sshd_config: HostbasedAuthentication no · IgnoreRhosts yes" "CIS v8 4.8"
    fi

    local cai
    cai=$(ssh_opt clientaliveinterval)
    if [[ -n "$cai" && "$cai" -gt 0 && "$cai" -le 900 ]]; then
        record SSH-009 PASS low "Sesiones inactivas se cierran (ClientAliveInterval $cai)" "" "" "CIS v8 4.3"
    else
        record SSH-009 WARN low "Sesiones SSH inactivas no expiran" \
            "Una terminal olvidada abierta es un acceso listo para usar." \
            "En sshd_config: ClientAliveInterval 15 · ClientAliveCountMax 3 (valores CIS)" "CIS v8 4.3"
    fi

    v=$(ssh_opt loglevel)
    if [[ "${v:-info}" =~ ^(info|verbose)$ ]]; then
        record SSH-010 PASS low "LogLevel ${v:-info}" "" "" "CIS v8 8.2"
    else
        record SSH-010 FAIL low "LogLevel de SSH insuficiente ($v)" "" \
            "En sshd_config: LogLevel VERBOSE (registra la huella de la llave usada)" "CIS v8 8.2"
    fi

    # SSH-011 Permisos de configuración y llaves privadas del servidor
    if [[ $IS_ROOT -eq 1 ]]; then
        local badperm
        badperm=$(
            find /etc/ssh -maxdepth 1 -name sshd_config -perm /022 2>/dev/null
            find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' -perm /077 2>/dev/null
        )
        if [[ -n "$badperm" ]]; then
            record SSH-011 FAIL high "Configuración o llaves privadas de SSH con permisos inseguros" \
                "$(join_list <<< "$badperm")" \
                "sudo chmod 600 /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key" "CIS v8 3.3 · MITRE T1552.004"
        else
            record SSH-011 PASS high "Configuración y llaves del servidor SSH protegidas" "" "" "CIS v8 3.3"
        fi

        # SSH-012 authorized_keys / .ssh de cada usuario
        local bad_keys="" root_keys=0 user home
        while IFS=: read -r user _ _ _ _ home _; do
            [[ -d "$home/.ssh" ]] || continue
            if [[ -n "$(find "$home/.ssh" -maxdepth 0 -perm /022 2>/dev/null)" ]]; then
                bad_keys+="$home/.ssh"$'\n'
            fi
            local ak
            for ak in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
                [[ -f "$ak" ]] || continue
                [[ -n "$(find "$ak" -maxdepth 0 -perm /022 2>/dev/null)" ]] && bad_keys+="$ak"$'\n'
                [[ "$user" == root ]] && root_keys=$(( root_keys + $(grep -cE '^(ssh-|ecdsa-|sk-)' "$ak" 2>/dev/null || echo 0) ))
            done
        done < /etc/passwd
        if [[ -n "$bad_keys" ]]; then
            record SSH-012 FAIL high "Llaves autorizadas modificables por otros usuarios" \
                "$(join_list <<< "$bad_keys"). Otro usuario podría agregar su llave y entrar como esa cuenta." \
                "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys" "CIS v8 6.1 · MITRE T1098.004"
        else
            record SSH-012 PASS high "Archivos authorized_keys protegidos" "" "" "CIS v8 6.1"
        fi
        if [[ $root_keys -gt 0 ]]; then
            record SSH-013 INFO none "root tiene $root_keys llave(s) SSH autorizada(s)" \
                "Verifica que todas sean conocidas: sudo cat /root/.ssh/authorized_keys" "" "MITRE T1098.004"
        fi
    else
        record SSH-011 SKIP none "Permisos de llaves SSH: requiere root"
        record SSH-012 SKIP none "authorized_keys: requiere root"
    fi

    # SSH-014 LoginGraceTime (CIS 5.1.13): tiempo para autenticarse
    v=$(ssh_opt logingracetime); v=${v:-120}
    v=${v%s}
    if [[ "$v" =~ ^[0-9]+$ && $v -ge 1 && $v -le 60 ]]; then
        record SSH-014 PASS low "LoginGraceTime ${v}s" "" "" "CIS v8 4.1"
    else
        record SSH-014 FAIL low "LoginGraceTime ${v}s (recomendado: 60 o menos)" \
            "Conexiones a medio autenticar ocupan recursos y facilitan la denegación de servicio." \
            "En sshd_config: LoginGraceTime 60" "CIS v8 4.1"
    fi

    # SSH-015 MaxSessions y MaxStartups (CIS 5.1.17, 5.1.18)
    local ms mst
    ms=$(ssh_opt maxsessions); ms=${ms:-10}
    mst=$(ssh_opt maxstartups); mst=${mst:-10:30:100}
    local mst_full=${mst##*:}
    if [[ "$ms" =~ ^[0-9]+$ && $ms -le 10 && "$mst_full" =~ ^[0-9]+$ && $mst_full -le 60 ]]; then
        record SSH-015 PASS low "MaxSessions $ms · MaxStartups $mst" "" "" "CIS v8 4.1"
    else
        record SSH-015 FAIL low "Límites de conexión SSH amplios (MaxSessions $ms · MaxStartups $mst)" \
            "CIS recomienda MaxSessions 10 o menos y MaxStartups 10:30:60 para resistir inundaciones." \
            "En sshd_config: MaxSessions 10 · MaxStartups 10:30:60" "CIS v8 4.1"
    fi

    # SSH-016 GSSAPIAuthentication (CIS 5.1.9)
    v=$(ssh_opt gssapiauthentication)
    if [[ "${v:-no}" == no ]]; then
        record SSH-016 PASS low "GSSAPIAuthentication no" "" "" "CIS v8 4.8"
    else
        record SSH-016 FAIL low "GSSAPIAuthentication activo" \
            "Solo es necesario en redes con Kerberos; si no, es superficie de ataque extra." \
            "En sshd_config: GSSAPIAuthentication no" "CIS v8 4.8"
    fi

    # SSH-017 UsePAM (CIS 5.1.22): sin PAM no se aplican bloqueos ni políticas
    v=$(ssh_opt usepam)
    if [[ "${v:-no}" == yes ]]; then
        record SSH-017 PASS medium "UsePAM yes" "" "" "CIS v8 5.2"
    else
        record SSH-017 FAIL medium "UsePAM desactivado" \
            "Sin PAM no se aplican el bloqueo tras intentos fallidos ni la política de contraseñas." \
            "En sshd_config: UsePAM yes" "CIS v8 5.2"
    fi
}

# =============================================================================
#  PRUEBAS — SISTEMA DE ARCHIVOS  (CIS Control 3 y 4)
# =============================================================================

# SUID esperados en Debian/Ubuntu/Kali. Lo que no esté aquí se revisa a mano.
SUID_BASELINE="passwd chsh chfn gpasswd newgrp su sudo sudoedit mount umount pkexec \
fusermount fusermount3 ssh-keysign dbus-daemon-launch-helper polkit-agent-helper-1 \
chrome-sandbox Xorg.wrap ntfs-3g pppd unix_chkpwd expiry chage crontab ssh-agent \
dotlockfile wall write at bsd-write mount.cifs mount.nfs snap-confine \
kismet_cap_linux_wifi kismet_cap_linux_bluetooth kismet_cap_nrf_51822 kismet_cap_nrf_mousejack \
kismet_cap_nxp_kw41z kismet_cap_rz_killerbee kismet_cap_ti_cc_2531 kismet_cap_ti_cc_2540 \
kismet_cap_ubertooth_one kismet_cap_hak5_wifi_coconut kismet_cap_nrf_52840 kismet_cap_ti_cc_2652 \
kismet_cap_linux_bt_hci newuidmap newgidmap vmware-user-suid-wrapper VBoxNetAdpCtl VBoxHeadless \
VBoxNetDHCP VBoxNetNAT VBoxSDL VBoxVolInfo VirtualBoxVM mlocate plocate locate ping ping6 traceroute6.iputils \
arping utempter ksu staprun Xorg exim4 procmail lockdev"

# Binarios que con SUID dan root directamente (fuente: GTFOBins)
SUID_DANGEROUS="bash sh dash zsh ksh csh tcsh fish find vim vi vim.basic vim.tiny nano less more \
cp mv python python2 python3 perl ruby php lua node nmap awk gawk mawk env tar zip unzip wget curl nc \
ncat netcat socat docker systemctl base64 tee dd sed openssl gdb strace taskset xargs time \
busybox git ed rsync scp tclsh expect make man journalctl watch ionice nice chroot install"

in_list() { [[ " $2 " == *" $1 "* ]]; }

check_fs() {
    # FS-001 Permisos y dueño de archivos críticos
    # formato: ruta:permiso_máximo:severidad
    local spec bad_crit="" bad_med=""
    for spec in /etc/passwd:644:critical /etc/group:644:high /etc/shadow:640:critical \
                /etc/gshadow:640:critical /etc/passwd-:644:medium /etc/shadow-:640:high \
                /etc/group-:644:medium /etc/gshadow-:640:high; do
        local f=${spec%%:*} rest=${spec#*:}
        local max=${rest%%:*} sev=${rest#*:}
        [[ -e "$f" ]] || continue
        local perm owner
        perm=$(stat -c '%a' "$f"); owner=$(stat -c '%U' "$f")
        if (( (8#$perm & ~8#$max) != 0 )) || [[ "$owner" != root ]]; then
            local line="$f ($perm, dueño $owner; máximo $max)"
            if [[ $sev == critical ]]; then bad_crit+="$line"$'\n'; else bad_med+="$line"$'\n'; fi
        fi
    done
    if [[ -n "$bad_crit" ]]; then
        record FS-001 FAIL critical "Archivos de cuentas/contraseñas con permisos inseguros" \
            "$(join_list <<< "$bad_crit$bad_med")" \
            "sudo chmod 644 /etc/passwd /etc/group && sudo chmod 640 /etc/shadow /etc/gshadow" \
            "CIS v8 3.3 · MITRE T1003.008"
    elif [[ -n "$bad_med" ]]; then
        record FS-001 FAIL medium "Copias de respaldo de archivos de cuentas con permisos amplios" \
            "$(join_list <<< "$bad_med")" "Ajusta permisos con chmod como indica el detalle" "CIS v8 3.3"
    else
        record FS-001 PASS critical "Archivos de cuentas y contraseñas protegidos" "" "" "CIS v8 3.3"
    fi

    # Un solo recorrido del disco para todas las pruebas de permisos.
    # Recorremos cada sistema de archivos local (no /proc, /sys, ni red).
    if [[ $IS_ROOT -eq 0 ]]; then
        local id
        for id in FS-002 FS-003 FS-004 FS-005 FS-006 FS-007; do
            record "$id" SKIP none "Recorrido completo del disco: requiere root"
        done
    else
        local mounts
        mounts=$(findmnt -rn -o TARGET -t ext2,ext3,ext4,xfs,btrfs,f2fs,jfs,reiserfs,zfs 2>/dev/null)
        [[ -z "$mounts" ]] && mounts="/"
        # /tmp, /var/tmp y /dev/shm suelen ser tmpfs (en Kali y Debian 13 /tmp lo es):
        # son justo donde un atacante deja sus binarios, así que también se recorren.
        local tm
        for tm in /tmp /var/tmp /dev/shm; do
            [[ "$(findmnt -n -o TARGET --target "$tm" 2>/dev/null | tail -n1)" == "$tm" ]] && mounts+=$'\n'"$tm"
        done
        local scan
        # -print0 / read -d '' soportan nombres de archivo con saltos de línea
        scan=$(
            while IFS= read -r mp; do
                timeout "$FIND_TIMEOUT" find "$mp" -xdev \
                    \( -path /proc -o -path /sys -o -path /run -o -path /dev \) -prune -o \
                    \( -type f -perm -4000 -printf 'SUID\t%p\n' \) -o \
                    \( -type f -perm -2000 -printf 'SGID\t%p\n' \) -o \
                    \( -type f -perm -0002 -printf 'WWF\t%m\t%p\n' \) -o \
                    \( -type d -perm -0002 ! -perm -1000 -printf 'WWD\t%p\n' \) -o \
                    \( \( -nouser -o -nogroup \) -printf 'NOOWN\t%p\n' \) 2>/dev/null
            done <<< "$mounts" | tr -d '\r' | sort -u
        )

        # FS-002 / FS-003 archivos escribibles por cualquiera.
        # CRÍTICO si está en rutas del sistema o es ejecutable (alguien con más
        # privilegios podría ejecutarlo). Ignoramos /tmp, /var/tmp y /dev/shm,
        # donde es lo esperado (directorios con sticky bit).
        local sysre='^/(etc|bin|sbin|usr|lib|lib32|lib64|libx32|boot|var/spool/cron)/'
        local wwf ww_crit ww_other
        wwf=$(awk -F'\t' '$1 == "WWF" {print $2 "\t" $3}' <<< "$scan" \
              | grep -vE $'\t''/(tmp|var/tmp|dev/shm)/' || true)
        ww_crit=""; ww_other=""
        local mode wpath
        while IFS=$'\t' read -r mode wpath; do
            [[ -z "$wpath" ]] && continue
            # 8#111 = algún bit de ejecución (dueño, grupo u otros)
            if [[ "$wpath" =~ $sysre ]] || (( 8#$mode & 8#111 )); then
                ww_crit+="$wpath"$'\n'
            else
                ww_other+="$wpath"$'\n'
            fi
        done <<< "$wwf"
        ww_crit=$(grep . <<< "$ww_crit" || true); ww_other=$(grep . <<< "$ww_other" || true)
        if [[ -n "$ww_crit" ]]; then
            record FS-002 FAIL critical "Archivos de sistema o ejecutables modificables por cualquier usuario" \
                "$(join_list 8 <<< "$ww_crit"). Si root o cron los ejecuta, cualquiera se vuelve root." \
                "sudo chmod o-w ARCHIVO" "CIS v8 3.3 · MITRE T1574, T1053.003"
        else
            record FS-002 PASS critical "Ningún archivo de sistema o ejecutable es modificable por cualquiera" "" "" "CIS v8 3.3"
        fi
        if [[ -n "$ww_other" ]]; then
            record FS-003 WARN medium "$(grep -c . <<< "$ww_other") archivo(s) de datos modificables por cualquier usuario" \
                "$(join_list 6 <<< "$ww_other")" "sudo chmod o-w ARCHIVO" "CIS v8 3.3"
        else
            record FS-003 PASS medium "Sin otros archivos modificables por cualquiera" "" "" "CIS v8 3.3"
        fi

        # FS-004 Directorios escribibles por todos sin sticky bit
        local wwd
        wwd=$(awk -F'\t' '$1 == "WWD" {print $2}' <<< "$scan")
        if [[ -n "$wwd" ]]; then
            record FS-004 FAIL medium "Directorios públicos sin sticky bit" \
                "$(join_list 6 <<< "$wwd"). Cualquiera puede borrar o reemplazar archivos de otros." \
                "sudo chmod +t DIRECTORIO" "CIS v8 3.3"
        else
            record FS-004 PASS medium "Directorios públicos con sticky bit" "" "" "CIS v8 3.3"
        fi

        # FS-005 Archivos sin dueño
        local noown
        noown=$(awk -F'\t' '$1 == "NOOWN" {print $2}' <<< "$scan")
        if [[ -n "$noown" ]]; then
            record FS-005 WARN medium "$(grep -c . <<< "$noown") archivo(s) sin dueño válido" \
                "$(join_list 5 <<< "$noown"). Un usuario nuevo con ese UID heredaría esos archivos." \
                "Asigna dueño: sudo chown root:root ARCHIVO (o bórralos si sobran)" "CIS v8 3.3"
        else
            record FS-005 PASS medium "Todos los archivos tienen dueño válido" "" "" "CIS v8 3.3"
        fi

        # FS-006 / FS-007 SUID y SGID
        # Un SUID se considera peligroso si:
        #  1) su nombre está en la lista de GTFOBins, o
        #  2) está en un directorio de usuarios o temporal (nunca es legítimo), o
        #  3) su CONTENIDO es idéntico a un binario peligroso aunque lo hayan
        #     renombrado (un atacante copia bash como ".cache" para esconderlo).
        local suid sgid danger="" unknown="" p b
        suid=$(awk -F'\t' '$1 == "SUID" {print $2}' <<< "$scan")
        sgid=$(awk -F'\t' '$1 == "SGID" {print $2}' <<< "$scan")
        local danger_hashes=""
        while IFS= read -r p; do
            [[ -z "$p" ]] && continue
            b=$(basename "$p")
            if in_list "$b" "$SUID_DANGEROUS" || [[ "$b" =~ ^python[0-9.]+$|^perl[0-9.]+$|^php[0-9.]+$ ]]; then
                danger+="$p"$'\n'
            elif [[ "$p" =~ ^/(tmp|var/tmp|dev/shm|home|root)/ ]]; then
                danger+="$p (ubicación sospechosa)"$'\n'
            elif ! in_list "$b" "$SUID_BASELINE"; then
                # Calculamos las huellas de los binarios peligrosos solo si hace falta
                if [[ -z "$danger_hashes" ]]; then
                    local n bin
                    danger_hashes=$(for n in $SUID_DANGEROUS; do
                        bin=$(type -P "$n" 2>/dev/null) && sha256sum "$(readlink -f "$bin")" 2>/dev/null
                    done | awk '{print $1}' | sort -u)
                    danger_hashes=${danger_hashes:-ninguno}
                fi
                local h
                h=$(sha256sum "$p" 2>/dev/null | awk '{print $1}')
                if [[ -n "$h" ]] && grep -qxF "$h" <<< "$danger_hashes"; then
                    danger+="$p (copia renombrada de un binario peligroso)"$'\n'
                else
                    unknown+="$p"$'\n'
                fi
            fi
        done <<< "$suid"
        if [[ -n "$danger" ]]; then
            record FS-006 FAIL critical "Binarios SUID que permiten volverse root" \
                "$(join_list <<< "$danger"). Ver gtfobins.github.io" \
                "sudo chmod u-s BINARIO (y averigua quién lo cambió)" "CIS v8 4.1 · MITRE T1548.001"
        else
            record FS-006 PASS critical "Ningún binario SUID peligroso" "" "" "CIS v8 4.1"
        fi
        # CIS 7.1.13 pide revisar los SUID. La pregunta clave de un auditor es:
        # ¿de dónde salió? Si lo instaló un paquete del sistema, es esperado;
        # si no pertenece a ningún paquete, alguien lo creó a mano.
        local orphan="" packaged="" upkg
        while IFS= read -r p; do
            [[ -z "$p" ]] && continue
            upkg=$(pkg_of "$p")
            if [[ -n "$upkg" ]]; then
                packaged+="$p (paquete $upkg)"$'\n'
            elif have dpkg-query; then
                orphan+="$p"$'\n'
            else
                packaged+="$p"$'\n'
            fi
        done <<< "$unknown"
        if [[ -n "$orphan" ]]; then
            record FS-007 FAIL high "Binarios SUID que no pertenecen a ningún paquete" \
                "$(join_list 8 <<< "$orphan"). Nadie los instaló con apt: pueden ser software manual o una puerta trasera.${packaged:+ Además, fuera de la lista estándar pero de paquetes: $(join_list 5 <<< "$packaged").}" \
                "Investiga su origen (ls -l, sha256sum, fecha de creación) y si no se justifica: sudo chmod u-s BINARIO" \
                "CIS v8 2.3 · MITRE T1548.001"
        elif [[ -n "$packaged" ]]; then
            record FS-007 WARN low "Binarios SUID poco comunes, instalados por paquetes" \
                "$(join_list 8 <<< "$packaged"). Son esperados mientras uses ese software." \
                "Si no usas el paquete, desinstálalo: sudo apt purge PAQUETE" \
                "CIS v8 2.3 · MITRE T1548.001"
        else
            record FS-007 PASS medium "Todos los binarios SUID son estándar" "" "" "CIS v8 2.3"
        fi
        record FS-008 INFO none "Inventario: $(grep -c . <<< "$suid" || true) SUID, $(grep -c . <<< "$sgid" || true) SGID"
    fi

    # FS-009 /tmp y /dev/shm: nosuid, nodev, noexec
    local mp opts missing
    for mp in /tmp /dev/shm; do
        local id=FS-009; [[ $mp == /dev/shm ]] && id=FS-010
        opts=$(findmnt -n -o OPTIONS --target "$mp" 2>/dev/null | tail -n1)
        local real
        real=$(findmnt -n -o TARGET --target "$mp" 2>/dev/null | tail -n1)
        if [[ "$real" != "$mp" ]]; then
            record "$id" WARN low "$mp no es una partición separada" \
                "No se le pueden aplicar nosuid/nodev/noexec." \
                "Monta $mp como tmpfs con: nosuid,nodev,noexec (ver systemd tmp.mount)" "CIS v8 4.1"
            continue
        fi
        missing=""
        local o
        for o in nosuid nodev noexec; do
            [[ ",$opts," == *",$o,"* ]] || missing+="$o "
        done
        if [[ -n "$missing" ]]; then
            record "$id" FAIL medium "$mp montado sin: ${missing% }" \
                "Los atacantes usan $mp para descargar y ejecutar herramientas. Ojo: con noexec, algunos instaladores o compiladores que ejecutan cosas en $mp pueden fallar; pruébalo antes en un snapshot." \
                "Agrega ${missing% } a las opciones de $mp (en /etc/fstab o con systemctl edit tmp.mount) y reinicia" "CIS v8 4.1 · MITRE T1059"
        else
            record "$id" PASS medium "$mp montado con nosuid,nodev,noexec" "" "" "CIS v8 4.1"
        fi
    done

    # FS-011 Directorios personales
    local home_bad_w="" home_bad_r="" user uid home
    while IFS=: read -r user _ uid _ _ home _; do
        [[ $uid -ge 1000 && $uid -lt 65534 && -d "$home" ]] || continue
        local hp
        hp=$(stat -c '%a' "$home" 2>/dev/null) || continue
        if (( 8#$hp & 8#002 )); then home_bad_w+="$home ($hp)"$'\n'
        elif (( 8#$hp & 8#005 )); then home_bad_r+="$home ($hp)"$'\n'
        fi
    done < /etc/passwd
    if [[ -n "$home_bad_w" ]]; then
        record FS-011 FAIL high "Directorios personales modificables por otros" \
            "$(join_list <<< "$home_bad_w")" "chmod 750 DIRECTORIO" "CIS v8 3.3 · MITRE T1546.004"
    elif [[ -n "$home_bad_r" ]]; then
        record FS-011 WARN low "Directorios personales legibles por otros usuarios" \
            "$(join_list <<< "$home_bad_r")" "chmod 750 DIRECTORIO" "CIS v8 3.3"
    else
        record FS-011 PASS high "Directorios personales privados" "" "" "CIS v8 3.3"
    fi

    # FS-012 PATH con directorios peligrosos ('.', vacío o escribible por otros)
    local entry path_bad="" path_entries=()
    # Una entrada vacía (al inicio, al final o '::') equivale al directorio actual
    if [[ "$ORIG_PATH" == :* || "$ORIG_PATH" == *: || "$ORIG_PATH" == *::* ]]; then
        path_bad+="entrada vacía (equivale al directorio actual)"$'\n'
    fi
    IFS=: read -ra path_entries <<< "$ORIG_PATH"
    for entry in "${path_entries[@]}"; do
        [[ -z "$entry" ]] && continue
        if [[ "$entry" == "." || "$entry" != /* ]]; then
            path_bad+="$entry (ruta relativa)"$'\n'
        elif [[ -d "$entry" && -n "$(find -L "$entry" -maxdepth 0 -perm /022 2>/dev/null)" ]]; then
            path_bad+="$entry (escribible por otros)"$'\n'
        fi
    done
    path_bad=$(grep . <<< "$path_bad" || true)
    if [[ -n "$path_bad" ]]; then
        record FS-012 FAIL high "PATH inseguro en la sesión que ejecuta la auditoría" \
            "$(join_list <<< "$path_bad"). Permite secuestrar comandos (ej. un 'ls' falso)." \
            "Quita esas entradas del PATH en ~/.bashrc o ~/.profile" "CIS v8 4.1 · MITRE T1574.007"
    else
        record FS-012 PASS high "PATH sin directorios peligrosos" "" "" "CIS v8 4.1"
    fi
}

# =============================================================================
#  PRUEBAS — KERNEL  (CIS Control 4: configuración segura)
# =============================================================================
check_krn() {
    # id|claves (separadas por coma: TODAS deben cumplir)|operador|valor|severidad|explicación
    local rules=(
        "KRN-001|kernel.randomize_va_space|eq|2|high|ASLR completo: dificulta explotar fallos de memoria"
        "KRN-002|fs.protected_symlinks|eq|1|medium|Evita ataques con enlaces simbólicos en /tmp"
        "KRN-003|fs.protected_hardlinks|eq|1|medium|Evita ataques con enlaces duros"
        "KRN-004|fs.suid_dumpable|eq|0|medium|Programas SUID no vuelcan memoria (podría contener secretos)"
        "KRN-005|kernel.dmesg_restrict|eq|1|low|Solo root lee los mensajes del kernel"
        "KRN-006|kernel.kptr_restrict|ge|1|low|Oculta direcciones del kernel a usuarios"
        "KRN-007|kernel.yama.ptrace_scope|ge|1|low|Un proceso no puede espiar la memoria de otro"
        "KRN-008|kernel.unprivileged_bpf_disabled|ge|1|low|Usuarios sin privilegios no cargan programas BPF"
        "KRN-009|net.ipv4.ip_forward,net.ipv6.conf.all.forwarding|eq|0|medium|El equipo no reenvía tráfico como un router"
        "KRN-010|net.ipv4.conf.all.send_redirects,net.ipv4.conf.default.send_redirects|eq|0|medium|No envía redirecciones ICMP"
        "KRN-011|net.ipv4.conf.all.accept_redirects,net.ipv4.conf.default.accept_redirects|eq|0|medium|Ignora redirecciones ICMP (evita desvíos de tráfico)"
        "KRN-012|net.ipv6.conf.all.accept_redirects,net.ipv6.conf.default.accept_redirects|eq|0|medium|Ignora redirecciones ICMPv6"
        "KRN-013|net.ipv4.conf.all.accept_source_route,net.ipv4.conf.default.accept_source_route,net.ipv6.conf.all.accept_source_route,net.ipv6.conf.default.accept_source_route|eq|0|medium|Rechaza paquetes con ruta impuesta por el emisor"
        "KRN-014|net.ipv4.conf.all.rp_filter,net.ipv4.conf.default.rp_filter|eq|1|low|Descarta paquetes con IP de origen falsificada"
        "KRN-015|net.ipv4.tcp_syncookies|eq|1|medium|Protege contra inundación SYN"
        "KRN-016|net.ipv4.conf.all.log_martians,net.ipv4.conf.default.log_martians|eq|1|low|Registra paquetes con direcciones imposibles"
        "KRN-017|net.ipv4.icmp_echo_ignore_broadcasts|eq|1|low|Ignora pings a broadcast (ataque smurf)"
        "KRN-018|net.ipv4.icmp_ignore_bogus_error_responses|eq|1|low|No llena los registros con respuestas ICMP falsas"
        "KRN-019|net.ipv4.conf.all.secure_redirects,net.ipv4.conf.default.secure_redirects|eq|0|medium|Ignora redirecciones aunque vengan del gateway"
        "KRN-020|net.ipv6.conf.all.accept_ra,net.ipv6.conf.default.accept_ra|eq|0|medium|No acepta anuncios de router IPv6 (evita rutas falsas)"
    )
    local r id keys op want sev why key cur bad missing fixcmd
    for r in "${rules[@]}"; do
        IFS='|' read -r id keys op want sev why <<< "$r"
        bad=""; missing=0; fixcmd=""
        for key in ${keys//,/ }; do
            cur=$(sysctl_get "$key")
            # Si IPv6 está deshabilitado, sus claves no existen: no es un fallo
            if [[ -z "$cur" ]]; then missing=$((missing + 1)); continue; fi
            if [[ $op == eq && "$cur" != "$want" ]] || \
               [[ $op == ge && ! ( "$cur" =~ ^[0-9]+$ && "$cur" -ge "$want" ) ]]; then
                bad+="$key = $cur, "
                fixcmd+="$key = $want\n"
            fi
        done
        local nkeys; nkeys=$(tr ',' '\n' <<< "$keys" | grep -c .)
        local first=${keys%%,*}
        if [[ $missing -eq $nkeys ]]; then
            record "$id" SKIP none "$first no existe en este kernel"
        elif [[ -z "$bad" ]]; then
            record "$id" PASS "$sev" "$first = $(sysctl_get "$first")$([[ $nkeys -gt 1 ]] && echo " (y variantes)")" "" "" "CIS v8 4.1"
        else
            local note="Para qué sirve: $why. Valores actuales: ${bad%, }."
            [[ $id == KRN-009 ]] && note+=" Es normal en hosts con Docker, VPN, máquinas virtuales anidadas o que actúan de router."
            [[ $id == KRN-020 ]] && note+=" Si este equipo obtiene su IPv6 por SLAAC (autoconfiguración), desactivarlo lo dejaría sin IPv6."
            [[ $id == KRN-007 ]] && note+=" Con valor 1, depuradores como gdb solo pueden adjuntarse a procesos hijos o usando sudo."
            local shown=$first; [[ $nkeys -gt 1 ]] && shown="$first y variantes"
            record "$id" FAIL "$sev" "$shown: valor inseguro (recomendado: $([[ $op == ge ]] && echo '≥ ')$want)" "$note" \
                "printf '$fixcmd' | sudo tee -a /etc/sysctl.d/60-linux-audit.conf && sudo sysctl --system" \
                "CIS v8 4.1"
        fi
    done
}

# =============================================================================
#  PRUEBAS — RED Y FIREWALL  (CIS Control 4.4, 4.5, 12, 13)
# =============================================================================
check_net() {
    # NET-001 Servicios expuestos a la red
    if have ss; then
        local listening exposed="" localonly=0
        if [[ $IS_ROOT -eq 1 ]]; then
            listening=$(ss -H -tulnp 2>/dev/null)
        else
            listening=$(ss -H -tuln 2>/dev/null)
        fi
        local proto local_addr procinfo port addr name
        while read -r proto _ _ _ local_addr _ procinfo; do
            [[ -z "${local_addr:-}" ]] && continue
            port=${local_addr##*:}; addr=${local_addr%:*}
            name=$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<< "${procinfo:-}")
            if [[ "$addr" =~ ^(127\.|\[::1\]|::1|\[::ffff:127\.) ]]; then
                localonly=$((localonly + 1))
            else
                exposed+="$proto/$port${name:+ ($name)}"$'\n'
            fi
        done <<< "$listening"
        exposed=$(sort -u <<< "$exposed" | grep . || true)
        if [[ -n "$exposed" ]]; then
            record NET-001 WARN medium "$(grep -c . <<< "$exposed") servicio(s) aceptan conexiones desde la red" \
                "$(join_list 12 <<< "$exposed"). $localonly más escuchan solo en localhost." \
                "Desactiva lo que no uses (systemctl disable --now SERVICIO) o limítalo con el firewall" \
                "CIS v8 4.8, 12.2 · MITRE T1133"
        else
            record NET-001 PASS medium "Ningún servicio expuesto a la red ($localonly solo locales)" "" "" "CIS v8 4.8"
        fi
    else
        record NET-001 SKIP none "Puertos: falta el comando ss (paquete iproute2)"
    fi

    # NET-002 Firewall activo
    if [[ $IS_ROOT -eq 0 ]]; then
        record NET-002 SKIP none "Estado del firewall: requiere root"
    else
        local fw="" ipv6_open=0
        if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
            fw="UFW"
        elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then
            fw="firewalld"
        elif have nft && nft list ruleset 2>/dev/null | grep -qE 'policy drop|\b(drop|reject)\b'; then
            fw="nftables"
        elif have iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; then
            fw="iptables"
            if [[ -f /proc/net/if_inet6 ]] && have ip6tables \
               && ! ip6tables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; then
                ipv6_open=1
            fi
        fi
        if [[ -z "$fw" ]]; then
            record NET-002 FAIL high "No hay firewall activo" \
                "Cualquier servicio que se abra por error queda expuesto." \
                "sudo apt install ufw && sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable" \
                "CIS v8 4.4, 4.5 · MITRE T1133"
        elif [[ $ipv6_open -eq 1 ]]; then
            record NET-002 FAIL high "Firewall ($fw) filtra IPv4 pero IPv6 está abierto" \
                "Un atacante en la red local puede entrar por IPv6." \
                "Aplica las mismas reglas con ip6tables o migra a nftables (tabla inet)" "CIS v8 4.4"
        else
            record NET-002 PASS high "Firewall activo ($fw)" "" "" "CIS v8 4.4"
        fi
    fi

    # NET-003 Interfaces en modo promiscuo (posible sniffer)
    if have ip; then
        local promisc
        promisc=$(ip -o link show 2>/dev/null | awk -F': ' '/PROMISC/ {print $2}' | cut -d@ -f1)
        if [[ -n "$promisc" ]]; then
            record NET-003 WARN medium "Interfaces en modo promiscuo" \
                "$(join_list <<< "$promisc"). Normal si usas Wireshark/tcpdump o bridges de VM; si no, alguien podría estar capturando tráfico." \
                "Verifica qué proceso lo activó: sudo ss -p y ps aux" "CIS v8 13.3 · MITRE T1040"
        else
            record NET-003 PASS medium "Ninguna interfaz en modo promiscuo" "" "" "CIS v8 13.3"
        fi
    fi
}

# =============================================================================
#  PRUEBAS — REGISTROS Y AUDITORÍA  (CIS Control 8)
# =============================================================================
svc_active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

check_log() {
    # LOG-001 Los registros sobreviven a un reinicio
    if svc_active rsyslog || svc_active syslog-ng || [[ -d /var/log/journal ]] \
       || grep -qsE '^[[:space:]]*Storage=persistent' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; then
        record LOG-001 PASS medium "Registros persistentes (sobreviven a reinicios)" "" "" "CIS v8 8.2"
    else
        record LOG-001 FAIL medium "Los registros se pierden al reiniciar" \
            "Sin historial no se puede investigar un incidente." \
            "sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald" \
            "CIS v8 8.2, 8.3 · MITRE T1070"
    fi

    # LOG-002 auditd
    if svc_active auditd; then
        record LOG-002 PASS medium "auditd activo" "" "" "CIS v8 8.5"
    else
        record LOG-002 FAIL medium "auditd no está activo" \
            "Sin auditd no hay registro detallado de quién cambió archivos críticos o usó privilegios." \
            "sudo apt install auditd && sudo systemctl enable --now auditd" "CIS v8 8.5"
    fi

    # LOG-003 Sincronización de hora (sin ella, los registros no sirven como evidencia)
    local synced=""
    if have timedatectl; then
        synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
    fi
    if [[ "$synced" == yes ]] || svc_active chrony || svc_active chronyd || svc_active ntp \
       || svc_active ntpsec || svc_active systemd-timesyncd; then
        record LOG-003 PASS medium "Hora sincronizada por red" "" "" "CIS v8 8.4"
    elif svc_active vboxadd-service || svc_active open-vm-tools || svc_active vmtoolsd \
         || svc_active hv-kvp-daemon || svc_active qemu-guest-agent; then
        record LOG-003 WARN low "La hora la sincroniza el hipervisor, no NTP" \
            "La VM copia el reloj del equipo anfitrión. Aceptable en un laboratorio; en servidores CIS pide chrony o systemd-timesyncd con servidores autorizados." \
            "sudo apt install chrony && sudo systemctl enable --now chrony" "CIS v8 8.4"
    else
        record LOG-003 WARN medium "No se detectó sincronización de hora" \
            "Horas incorrectas impiden correlacionar eventos entre equipos." \
            "sudo apt install chrony && sudo systemctl enable --now chrony" "CIS v8 8.4"
    fi

    # LOG-004 Permisos de /var/log
    if [[ -d /var/log ]]; then
        local wwlog
        wwlog=$(find /var/log -xdev -type f -perm -0002 2>/dev/null | head -n 20)
        if [[ -n "$wwlog" ]]; then
            record LOG-004 FAIL high "Registros modificables por cualquier usuario" \
                "$(join_list <<< "$wwlog"). Un atacante podría borrar sus huellas." \
                "sudo chmod o-w ARCHIVO" "CIS v8 8.3 · MITRE T1070.002"
        else
            record LOG-004 PASS high "Registros protegidos contra modificación" "" "" "CIS v8 8.3"
        fi
    fi

    # LOG-005 Intentos fallidos de acceso (últimos 7 días)
    local failed="" src=""
    local pattern='Failed password|authentication failure|Invalid user|maximum authentication attempts'
    if [[ $IS_ROOT -eq 1 ]] && have journalctl && journalctl -n1 -q >/dev/null 2>&1; then
        failed=$(timeout 60 journalctl --since "7 days ago" --no-pager -q 2>/dev/null | grep -E "$pattern" || true)
        src="journal, 7 días"
    elif [[ -r /var/log/auth.log ]]; then
        failed=$(grep -E "$pattern" /var/log/auth.log 2>/dev/null || true)
        src="/var/log/auth.log"
    fi
    if [[ -z "$src" ]]; then
        record LOG-005 SKIP none "Intentos de acceso: requiere root"
    else
        local count top
        count=$(grep -c . <<< "$failed" || true)
        top=$(grep -oE 'from [0-9a-fA-F:.]+' <<< "$failed" | awk '{print $2}' | sort | uniq -c \
              | sort -rn | head -n5 | awk '{print $2 " (" $1 ")"}' | join_list)
        if [[ $count -ge 50 ]]; then
            record LOG-005 FAIL medium "$count intentos de acceso fallidos ($src)" \
                "Probable fuerza bruta. IPs principales: ${top:-n/d}" \
                "Instala fail2ban o crowdsec y deshabilita contraseñas en SSH" "CIS v8 8.11 · MITRE T1110"
        elif [[ $count -gt 0 ]]; then
            record LOG-005 INFO none "$count intentos de acceso fallidos ($src)" "IPs: ${top:-locales}" "" "CIS v8 8.11"
        else
            record LOG-005 PASS medium "Sin intentos de acceso fallidos ($src)" "" "" "CIS v8 8.11"
        fi
    fi

    # LOG-006 Protección contra fuerza bruta si SSH está activo
    if svc_active ssh || svc_active sshd; then
        if svc_active fail2ban || svc_active crowdsec; then
            record LOG-006 PASS medium "Protección contra fuerza bruta activa" "" "" "CIS v8 13.3"
        else
            record LOG-006 WARN medium "SSH activo sin fail2ban/crowdsec" \
                "Nada bloquea a quien intente miles de contraseñas." \
                "sudo apt install fail2ban && sudo systemctl enable --now fail2ban" "CIS v8 13.3 · MITRE T1110"
        fi
    fi

    # LOG-007 Integridad de archivos (CIS 6.3.1): detecta binarios o
    # configuraciones alterados por un atacante.
    if have dpkg-query && ! dpkg-query -W -f='${Status}' aide 2>/dev/null | grep -q 'install ok installed'; then
        record LOG-007 WARN medium "Sin verificación de integridad de archivos (AIDE)" \
            "Si un atacante reemplaza un binario o una configuración, nada lo detectaría." \
            "sudo apt install aide && sudo aideinit (luego programa una revisión diaria)" \
            "CIS v8 3.14 · MITRE T1565"
    elif have dpkg-query; then
        record LOG-007 PASS medium "AIDE instalado" "" "" "CIS v8 3.14"
    fi
}

# =============================================================================
#  PRUEBAS — SERVICIOS Y TAREAS PROGRAMADAS  (CIS Control 4.8)
# =============================================================================
check_svc() {
    if ! have systemctl || ! systemctl list-units --no-pager >/dev/null 2>&1; then
        record SVC-001 SKIP none "Servicios: systemd no disponible"
    else
        # Protocolos que envían contraseñas en texto plano o sin autenticación
        local cleartext="" svc
        for svc in telnet.socket inetd xinetd rsh.socket rlogin.socket rexec.socket tftpd-hpa \
                   atftpd vsftpd proftpd pure-ftpd; do
            svc_active "$svc" && cleartext+="$svc"$'\n'
        done
        if [[ -n "$cleartext" ]]; then
            record SVC-001 FAIL high "Servicios inseguros (texto plano) activos" \
                "$(join_list <<< "$cleartext")" \
                "Reemplázalos por SSH/SFTP y desactívalos: sudo systemctl disable --now SERVICIO" \
                "CIS v8 4.8 · MITRE T1040"
        else
            record SVC-001 PASS high "Sin servicios de texto plano (telnet, rsh, FTP, TFTP)" "" "" "CIS v8 4.8"
        fi

        # CIS 2.1.x: servicios de servidor que no deberían correr si no se usan
        local optional=""
        for svc in rpcbind nfs-server smbd nmbd snmpd slapd bind9 named dnsmasq \
                   isc-dhcp-server kea-dhcp4-server dovecot apache2 nginx lighttpd \
                   mysql mariadb postgresql redis-server mongod squid rsync xrdp vncserver; do
            svc_active "$svc" && optional+="$svc"$'\n'
        done
        if [[ -n "$optional" ]]; then
            record SVC-002 WARN low "Servicios de servidor activos: confirma que sean necesarios" \
                "$(join_list 12 <<< "$optional"). Si los usas a propósito, es correcto; documéntalos como aceptados." \
                "Desactiva los que no uses: sudo systemctl disable --now SERVICIO" "CIS v8 4.8"
        else
            record SVC-002 PASS low "Sin servicios de servidor innecesarios activos" "" "" "CIS v8 4.8"
        fi

        # CIS 2.1.1, 2.1.2, 2.1.11, 3.1.3: servicios de escritorio. Son Nivel 1 en
        # servidores (no deberían existir) y Nivel 2 en estaciones de trabajo
        # (imprimir o usar Bluetooth en un portátil es normal).
        local desk=""
        for svc in avahi-daemon cups cups-browsed autofs bluetooth; do
            svc_active "$svc" && desk+="$svc"$'\n'
        done
        if [[ -n "$desk" ]]; then
            record SVC-007 WARN low "Servicios de escritorio activos" \
                "$(join_list <<< "$desk"). Anuncian el equipo en la red local o amplían la superficie de ataque." \
                "Si no imprimes ni usas Bluetooth: sudo systemctl disable --now SERVICIO" "CIS v8 4.8"
        else
            record SVC-007 PASS low "Sin servicios de escritorio activos" "" "" "CIS v8 4.8"
        fi

        local failedu
        failedu=$(systemctl --failed --no-legend --plain --no-pager 2>/dev/null | awk '{print $1}')
        if [[ -n "$failedu" ]]; then
            record SVC-003 INFO none "Servicios con error" "$(join_list <<< "$failedu")"
        fi
    fi

    # SVC-004 Permisos de cron (CIS)
    local crons=() c bad=""
    [[ -e /etc/crontab ]] && crons+=("/etc/crontab:600")
    for c in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [[ -d "$c" ]] && crons+=("$c:700")
    done
    local spec f max perm
    for spec in "${crons[@]}"; do
        f=${spec%%:*}; max=${spec##*:}
        perm=$(stat -c '%a' "$f")
        if (( (8#$perm & ~8#$max) != 0 )) || [[ "$(stat -c '%U' "$f")" != root ]]; then
            bad+="$f ($perm)"$'\n'
        fi
    done
    if [[ -n "$bad" ]]; then
        local sev=low
        # Escribible por grupo/otros = cualquiera programa tareas como root
        grep -qE '\(([0-7][2367][0-7]|[0-7][0-7][2367])\)' <<< "$bad" && sev=critical
        record SVC-004 FAIL "$sev" "Permisos de cron más amplios que lo recomendado" \
            "$(join_list <<< "$bad")" \
            "sudo chmod 600 /etc/crontab && sudo chmod 700 /etc/cron.{hourly,daily,weekly,monthly,d}" \
            "CIS v8 4.1 · MITRE T1053.003"
    elif [[ ${#crons[@]} -gt 0 ]]; then
        record SVC-004 PASS low "Archivos de cron protegidos" "" "" "CIS v8 4.1"
    fi

    # SVC-005 Unidades systemd modificables por no-root (persistencia / escalada)
    if [[ $IS_ROOT -eq 1 ]]; then
        local badunits
        badunits=$(find /etc/systemd /lib/systemd/system /usr/lib/systemd/system -xdev \
                   \( -type f -o -type d \) \( -perm -0002 -o \( -perm -0020 ! -group root \) \) 2>/dev/null | head -n 20)
        if [[ -n "$badunits" ]]; then
            record SVC-005 FAIL critical "Archivos de systemd modificables por otros usuarios" \
                "$(join_list <<< "$badunits"). Permite crear un servicio que corra como root." \
                "sudo chmod go-w RUTA && sudo chown root:root RUTA" "CIS v8 4.1 · MITRE T1543.002"
        else
            record SVC-005 PASS critical "Unidades systemd protegidas" "" "" "CIS v8 4.1"
        fi
    fi

    # SVC-006 Clientes de protocolos sin cifrado (CIS 2.2.1-2.2.6)
    if have dpkg-query; then
        local clients="" pk
        for pk in nis rsh-client rsh-redone-client talk inetutils-talk telnet inetutils-telnet ldap-utils ftp tnftp; do
            dpkg-query -W -f='${Status}' "$pk" 2>/dev/null | grep -q 'install ok installed' && clients+="$pk"$'\n'
        done
        if [[ -n "$clients" ]]; then
            record SVC-006 WARN low "Clientes de protocolos sin cifrado instalados" \
                "$(join_list <<< "$clients"). Envían contraseñas en texto plano. En Kali son herramientas de pentest habituales; en un servidor de producción no deberían estar." \
                "Si no los usas: sudo apt purge PAQUETE" "CIS v8 4.8 · MITRE T1040"
        else
            record SVC-006 PASS low "Sin clientes de protocolos inseguros (rsh, telnet, FTP...)" "" "" "CIS v8 4.8"
        fi
    fi
}

# =============================================================================
#  PRUEBAS — CONTROL DE ACCESO OBLIGATORIO (AppArmor / SELinux)
# =============================================================================
check_mac() {
    if have getenforce && [[ "$(getenforce 2>/dev/null)" == Enforcing ]]; then
        record MAC-001 PASS medium "SELinux en modo Enforcing" "" "" "CIS v8 4.1"
    elif [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == Y ]]; then
        local enforced=""
        if [[ $IS_ROOT -eq 1 ]] && have aa-status; then
            enforced=$(aa-status --enforced 2>/dev/null)
        fi
        if [[ -z "$enforced" || "$enforced" -gt 0 ]]; then
            record MAC-001 PASS medium "AppArmor habilitado${enforced:+ ($enforced perfiles en modo enforce)}" "" "" "CIS v8 4.1"
        else
            record MAC-001 FAIL medium "AppArmor habilitado pero sin perfiles aplicados" "" \
                "sudo apt install apparmor-profiles apparmor-utils && sudo aa-enforce /etc/apparmor.d/*" "CIS v8 4.1"
        fi
    else
        record MAC-001 FAIL medium "Ni AppArmor ni SELinux están activos" \
            "Si un servicio es comprometido, nada limita lo que puede hacer en el sistema." \
            "sudo apt install apparmor apparmor-utils y agrega 'apparmor=1 security=apparmor' al kernel en GRUB" \
            "CIS v8 4.1 · MITRE T1068"
    fi
}

# =============================================================================
#  PRUEBAS — ARRANQUE
# =============================================================================
check_boot() {
    local cfg=""
    for cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do [[ -f "$cfg" ]] && break; cfg=""; done
    if [[ -z "$cfg" ]]; then
        record BOOT-001 SKIP none "GRUB no encontrado"
        return
    fi
    local perm
    perm=$(stat -c '%a' "$cfg")
    if (( (8#$perm & 8#077) == 0 )); then
        record BOOT-001 PASS low "$cfg con permisos $perm" "" "" "CIS v8 4.1"
    else
        record BOOT-001 WARN low "$cfg legible por otros usuarios ($perm)" "" \
            "sudo chmod 600 $cfg" "CIS v8 4.1"
    fi
    if [[ $IS_ROOT -eq 1 ]]; then
        if grep -qE '^[[:space:]]*(set superusers|password_pbkdf2)' "$cfg" 2>/dev/null; then
            record BOOT-002 PASS low "GRUB protegido con contraseña" "" "" "CIS v8 4.1"
        else
            record BOOT-002 WARN low "GRUB sin contraseña" \
                "Con acceso físico o a la consola de la VM se puede arrancar como root." \
                "grub-mkpasswd-pbkdf2 y configúralo en /etc/grub.d/40_custom" "CIS v8 4.1 · MITRE T1542"
        fi
    fi
}

# =============================================================================
#  PRUEBAS — CONTENEDORES
# =============================================================================
check_cnt() {
    local members=""
    if getent group docker >/dev/null 2>&1; then
        members=$(getent group docker | cut -d: -f4)
        if [[ -n "$members" ]]; then
            record CNT-001 WARN high "Usuarios en el grupo docker: ${members//,/, }" \
                "Pertenecer al grupo docker equivale a ser root (docker run -v /:/host)." \
                "Quita a quien no lo necesite: sudo gpasswd -d USUARIO docker · o usa Docker rootless" \
                "CIS v8 5.4 · MITRE T1611"
        else
            record CNT-001 PASS high "Grupo docker sin miembros" "" "" "CIS v8 5.4"
        fi
    fi
    local sock
    for sock in /var/run/docker.sock /run/podman/podman.sock; do
        [[ -S "$sock" ]] || continue
        if [[ -n "$(find "$sock" -maxdepth 0 -perm -0002 2>/dev/null)" ]]; then
            record CNT-002 FAIL critical "$sock accesible por cualquier usuario" \
                "Cualquier usuario local puede volverse root." \
                "sudo chmod 660 $sock" "CIS v8 5.4 · MITRE T1611"
        else
            record CNT-002 PASS critical "$sock con permisos restringidos" "" "" "CIS v8 5.4"
        fi
    done
    if have ss && ss -H -tln 2>/dev/null | awk '{print $4}' | grep -qE '[:.]2375$'; then
        record CNT-003 FAIL critical "API de Docker expuesta sin TLS (puerto 2375)" \
            "Cualquiera en la red puede controlar Docker y tomar el equipo." \
            "Quita '-H tcp://0.0.0.0:2375' del servicio de Docker o usa TLS (2376)" "CIS v8 4.6 · MITRE T1610"
    fi
}

# =============================================================================
#  INFORMES
# =============================================================================
SCORE=0; N_PASS=0; N_WARN=0; N_FAIL=0; N_SKIP=0; N_INFO=0; N_L2=0; N_ACC=0
declare -A N_SEV=([critical]=0 [high]=0 [medium]=0 [low]=0)

compute_score() {
    local i got=0 max=0 w
    for i in "${!R_ID[@]}"; do
        w=$(sev_weight "${R_SEV[$i]}")
        case "${R_STATUS[$i]}" in
            PASS) N_PASS=$((N_PASS+1)); got=$((got + w*2)); max=$((max + w*2)) ;;
            WARN) N_WARN=$((N_WARN+1)); got=$((got + w)); max=$((max + w*2))
                  N_SEV[${R_SEV[$i]}]=$(( ${N_SEV[${R_SEV[$i]}]:-0} + 1 )) ;;
            FAIL) N_FAIL=$((N_FAIL+1)); max=$((max + w*2))
                  N_SEV[${R_SEV[$i]}]=$(( ${N_SEV[${R_SEV[$i]}]:-0} + 1 )) ;;
            SKIP) N_SKIP=$((N_SKIP+1)) ;;
            L2)   N_L2=$((N_L2+1)) ;;
            ACCEPT) N_ACC=$((N_ACC+1)) ;;
            *)    N_INFO=$((N_INFO+1)) ;;
        esac
    done
    [[ $max -gt 0 ]] && SCORE=$(( got * 100 / max ))
}

# Índices ordenados: FAIL/WARN primero por severidad, luego el resto
sorted_indices() {
    local i st rank
    for i in "${!R_ID[@]}"; do
        st=${R_STATUS[$i]}
        case "$st" in FAIL) rank=0 ;; WARN) rank=1 ;; L2) rank=2 ;; ACCEPT) rank=3 ;; PASS) rank=4 ;; INFO) rank=5 ;; *) rank=6 ;; esac
        printf '%d\t%d\t%s\t%d\n' "$rank" "$((5 - $(sev_num "${R_SEV[$i]}")))" "${R_ID[$i]}" "$i"
    done | sort -t$'\t' -k1,1n -k2,2n -k3,3 | cut -f4
}

summary_text() {
    local color=$1 g="" y="" r="" m="" b="" x=""
    [[ $color -eq 1 ]] && { g=$C_GRN; y=$C_YEL; r=$C_RED; m=$C_MAG; b=$C_BLD; x=$C_RST; }
    local sc=$g; [[ $SCORE -lt 80 ]] && sc=$y; [[ $SCORE -lt 60 ]] && sc=$r
    printf '\n%s== Resumen ==%s\n' "$b" "$x"
    printf '  Puntaje: %s%s%d/100%s   (ponderado por severidad)\n' "$b" "$sc" "$SCORE" "$x"
    local pl="Servidor"; [[ "$PROFILE" == workstation ]] && pl="Estación de trabajo"
    printf '  Perfil: %s · Nivel CIS %d\n' "$pl" "$LEVEL"
    printf '  OK %d · Avisos %d · Fallos %d · Omitidas %d · Informativas %d\n' \
        "$N_PASS" "$N_WARN" "$N_FAIL" "$N_SKIP" "$N_INFO"
    if [[ $N_L2 -gt 0 || $N_ACC -gt 0 ]]; then
        printf '  No restan puntos: %d recomendaciones de Nivel 2 (opcionales) · %d riesgos aceptados\n' "$N_L2" "$N_ACC"
    fi
    printf '  Problemas por severidad: %sCRÍTICO %d%s · %sALTO %d%s · MEDIO %d · BAJO %d\n' \
        "$m" "${N_SEV[critical]}" "$x" "$r" "${N_SEV[high]}" "$x" "${N_SEV[medium]}" "${N_SEV[low]}"
    if [[ ${N_SEV[critical]} -gt 0 || ${N_SEV[high]} -gt 0 ]]; then
        printf '\n  %sPrioridad: corrige primero los CRÍTICOS y ALTOS:%s\n' "$b" "$x"
        local i
        for i in $(sorted_indices); do
            [[ "${R_STATUS[$i]}" =~ ^(FAIL|WARN)$ ]] || continue
            [[ "${R_SEV[$i]}" =~ ^(critical|high)$ ]] || continue
            printf '   - %-8s %s\n' "${R_ID[$i]}" "${R_TITLE[$i]}"
        done
    fi
    [[ $IS_ROOT -eq 0 ]] && printf '\n  Ejecuta con sudo para una auditoría completa.\n'
    echo
}

render_text() {
    local i cat=""
    printf 'linux-audit v%s — %s — %s\n' "$VERSION" "$(hostname)" "$(date '+%Y-%m-%d %H:%M %Z')"
    for i in "${!R_ID[@]}"; do
        if [[ "${R_CAT[$i]}" != "$cat" ]]; then
            cat=${R_CAT[$i]}
            printf '\n== %s ==\n' "$(cat_label "$cat")"
        fi
        format_line "$i" 0
        [[ -n "${R_REF[$i]}" && "${R_STATUS[$i]}" =~ ^(FAIL|WARN|L2|ACCEPT)$ ]] && printf '  %-10s %-8s Ref: %s\n' "" "" "${R_REF[$i]}"
    done
    summary_text 0
}

json_esc() {
    local s=$1
    s=${s//\\/\\\\}; s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/\\r}
    printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

render_json() {
    local os; os=$(os_name)
    printf '{\n'
    printf '  "tool": "linux-audit",\n  "version": "%s",\n' "$VERSION"
    printf '  "host": "%s",\n' "$(json_esc "$(hostname)")"
    printf '  "os": "%s",\n  "kernel": "%s",\n' "$(json_esc "$os")" "$(json_esc "$(uname -r)")"
    printf '  "timestamp": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "run_as_root": %s,\n' "$([[ $IS_ROOT -eq 1 ]] && echo true || echo false)"
    printf '  "profile": "%s",\n  "cis_level": %d,\n' "$PROFILE" "$LEVEL"
    printf '  "exceptions_file": "%s",\n' "$(json_esc "$EXC_FILE")"
    printf '  "score": %d,\n' "$SCORE"
    printf '  "summary": {"pass": %d, "warn": %d, "fail": %d, "skip": %d, "info": %d, "level2": %d, "accepted": %d, ' \
        "$N_PASS" "$N_WARN" "$N_FAIL" "$N_SKIP" "$N_INFO" "$N_L2" "$N_ACC"
    printf '"critical": %d, "high": %d, "medium": %d, "low": %d},\n' \
        "${N_SEV[critical]}" "${N_SEV[high]}" "${N_SEV[medium]}" "${N_SEV[low]}"
    printf '  "findings": [\n'
    local i first=1
    for i in "${!R_ID[@]}"; do
        [[ $first -eq 1 ]] && first=0 || printf ',\n'
        printf '    {"id": "%s", "category": "%s", "status": "%s", "severity": "%s", "cis_level": "%s", ' \
            "${R_ID[$i]}" "$(json_esc "$(cat_label "${R_CAT[$i]}")")" "${R_STATUS[$i]}" "${R_SEV[$i]}" "${R_LVL[$i]}"
        printf '"title": "%s", "detail": "%s", "remediation": "%s", "references": "%s"}' \
            "$(json_esc "${R_TITLE[$i]}")" "$(json_esc "${R_DETAIL[$i]}")" \
            "$(json_esc "${R_FIX[$i]}")" "$(json_esc "${R_REF[$i]}")"
    done
    printf '\n  ]\n}\n'
}

html_esc() {
    local s=$1
    s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; s=${s//\"/&quot;}; s=${s//\'/&#39;}
    printf '%s' "$s"
}

render_html() {
    local host os date
    host=$(html_esc "$(hostname)")
    os=$(html_esc "$(os_name)")
    date=$(date '+%Y-%m-%d %H:%M %Z')
    local scls=good; [[ $SCORE -lt 80 ]] && scls=mid; [[ $SCORE -lt 60 ]] && scls=bad
    cat <<EOF
<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de seguridad — ${host}</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#6b7280;--line:#e5e7eb;
--crit:#7e22ce;--high:#dc2626;--med:#d97706;--low:#2563eb;--ok:#16a34a}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e5e7eb;--mut:#9ca3af;--line:#2a303b}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:1000px;margin:0 auto;padding:24px 16px}
header{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between}
h1{font-size:22px;margin:0}.mut{color:var(--mut);font-size:13px}
.conf{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--high);font-weight:700}
.score{font-size:44px;font-weight:800;line-height:1}.score small{font-size:16px;color:var(--mut)}
.good{color:var(--ok)}.mid{color:var(--med)}.bad{color:var(--high)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.card b{display:block;font-size:24px}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:10px 14px}
summary{cursor:pointer;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.tag{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;color:#fff;white-space:nowrap}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}
.PASS{background:var(--ok)}.none{background:var(--mut)}.lvl2{background:#64748b}.acc{background:#0f766e}
.lvl{font-size:11px;border:1px solid var(--line);border-radius:6px;padding:1px 6px;color:var(--mut)}
.id{font-family:ui-monospace,monospace;font-size:12px;color:var(--mut)}
.fix{font-family:ui-monospace,monospace;font-size:13px;background:var(--bg);padding:8px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
h2{font-size:17px;margin:28px 0 8px}
footer{margin-top:32px;font-size:12px;color:var(--mut)}
</style></head><body><main>
<p class="conf">Confidencial · contiene información sensible del equipo</p>
<header><div><h1>Informe de seguridad: ${host}</h1>
<div class="mut">Perfil: $([[ "$PROFILE" == workstation ]] && echo "Estación de trabajo" || echo "Servidor") · Nivel CIS ${LEVEL} · ${N_L2} recomendaciones de Nivel 2 · ${N_ACC} riesgos aceptados</div>
<div class="mut">${os} · kernel $(html_esc "$(uname -r)") · ${date} · linux-audit v${VERSION}$([[ $IS_ROOT -eq 0 ]] && echo ' · <b>ejecutado sin root (incompleto)</b>')</div></div>
<div class="score ${scls}">${SCORE}<small>/100</small></div></header>
<div class="cards">
<div class="card"><span class="mut">Críticos</span><b style="color:var(--crit)">${N_SEV[critical]}</b></div>
<div class="card"><span class="mut">Altos</span><b style="color:var(--high)">${N_SEV[high]}</b></div>
<div class="card"><span class="mut">Medios</span><b style="color:var(--med)">${N_SEV[medium]}</b></div>
<div class="card"><span class="mut">Bajos</span><b style="color:var(--low)">${N_SEV[low]}</b></div>
<div class="card"><span class="mut">Superadas</span><b style="color:var(--ok)">${N_PASS}</b></div>
</div>
EOF
    local i section="" st sev
    for i in $(sorted_indices); do
        st=${R_STATUS[$i]}; sev=${R_SEV[$i]}
        local want
        case "$st" in
            FAIL|WARN) want="Hallazgos por corregir" ;;
            L2)        want="Recomendaciones de Nivel 2 (opcionales, no restan puntos)" ;;
            ACCEPT)    want="Riesgos aceptados y documentados" ;;
            PASS)      want="Controles superados" ;;
            *)         want="Información y pruebas omitidas" ;;
        esac
        if [[ "$want" != "$section" ]]; then section=$want; printf '<h2>%s</h2>\n' "$section"; fi
        local tagcls tagtxt
        if [[ "$st" == FAIL || "$st" == WARN ]]; then
            tagcls=$sev; tagtxt="$(status_label "$st") · $(sev_label "$sev")"
        elif [[ "$st" == PASS ]]; then tagcls=PASS; tagtxt="OK"
        elif [[ "$st" == L2 ]]; then tagcls=lvl2; tagtxt="NIVEL 2"
        elif [[ "$st" == ACCEPT ]]; then tagcls=acc; tagtxt="ACEPTADO"
        else tagcls=none; tagtxt=$(status_label "$st"); fi
        printf '<details%s><summary><span class="tag %s">%s</span><span class="id">%s</span><span>%s</span><span class="lvl">%s</span></summary>\n' \
            "$([[ "$st" == FAIL && ( "$sev" == critical || "$sev" == high ) ]] && echo ' open')" \
            "$tagcls" "$(html_esc "$tagtxt")" "${R_ID[$i]}" "$(html_esc "${R_TITLE[$i]}")" "${R_LVL[$i]}"
        [[ -n "${R_DETAIL[$i]}" ]] && printf '<p>%s</p>\n' "$(html_esc "${R_DETAIL[$i]}")"
        [[ -n "${R_FIX[$i]}" && "$st" =~ ^(FAIL|WARN|L2)$ ]] && printf '<div class="fix">%s</div>\n' "$(html_esc "${R_FIX[$i]}")"
        [[ -n "${R_REF[$i]}" ]] && printf '<p class="mut">Referencias: %s</p>\n' "$(html_esc "${R_REF[$i]}")"
        printf '</details>\n'
    done
    cat <<EOF
<footer>Generado por linux-audit v${VERSION}. Auditoría automatizada de solo lectura: no sustituye una revisión manual ni una prueba de penetración. Referencias: CIS Critical Security Controls v8, MITRE ATT&amp;CK.</footer>
</main></body></html>
EOF
}

# =============================================================================
#  PROGRAMA PRINCIPAL
# =============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--format)  [[ -n "${2:-}" ]] || die "--format necesita un valor"; FORMAT=$2; shift 2 ;;
            -o|--output)  [[ -n "${2:-}" ]] || die "--output necesita un archivo"; OUTPUT_FILE=$2; shift 2 ;;
            --only)       [[ -n "${2:-}" ]] || die "--only necesita categorías"; ONLY=${2,,}; shift 2 ;;
            --fail-on)    [[ -n "${2:-}" ]] || die "--fail-on necesita una severidad"; FAIL_ON=${2,,}; shift 2 ;;
            --level)      [[ "${2:-}" =~ ^[12]$ ]] || die "--level debe ser 1 o 2"; LEVEL=$2; shift 2 ;;
            --profile)    [[ "${2:-}" =~ ^(server|workstation)$ ]] || die "--profile debe ser server o workstation"
                          PROFILE=$2; PROFILE_WHY="elegido con --profile"; shift 2 ;;
            --exceptions) [[ -n "${2:-}" ]] || die "--exceptions necesita un archivo"; EXC_FILE=$2; shift 2 ;;
            --list-checks) list_checks; exit 0 ;;
            -q|--quiet)   QUIET=1; shift ;;
            --no-color)   USE_COLOR=0; shift ;;
            -h|--help)    usage; exit 0 ;;
            -v|--version) echo "linux-audit v${VERSION}"; exit 0 ;;
            *) printf 'Opción desconocida: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
        esac
    done
    [[ "$FORMAT" =~ ^(text|json|html)$ ]] || die "formato no válido: $FORMAT (usa text, json o html)"
    [[ "$FAIL_ON" =~ ^(low|medium|high|critical)$ ]] || die "severidad no válida: $FAIL_ON"
    if [[ -n "$ONLY" ]]; then
        local c
        for c in ${ONLY//,/ }; do
            [[ "$c" =~ ^(sys|upd|acc|ssh|fs|krn|net|log|svc|mac|boot|cnt)$ ]] || die "categoría desconocida: $c"
        done
    fi
    if [[ -n "$OUTPUT_FILE" ]]; then
        # Protección contra ataques de enlace simbólico al escribir como root
        [[ -L "$OUTPUT_FILE" ]] && die "$OUTPUT_FILE es un enlace simbólico; por seguridad no se escribe en él"
        [[ -d "$OUTPUT_FILE" ]] && die "$OUTPUT_FILE es un directorio"
        local dir; dir=$(dirname -- "$OUTPUT_FILE")
        [[ -d "$dir" && -w "$dir" ]] || die "no se puede escribir en el directorio $dir"
    fi
}

want_cat() { [[ -z "$ONLY" || ",$ONLY," == *",$1,"* ]]; }

main() {
    parse_args "$@"
    [[ -t 1 ]] || USE_COLOR=0
    # En json/html por stdout no mezclamos texto en vivo con el documento
    if [[ "$FORMAT" != text && -z "$OUTPUT_FILE" ]]; then LIVE=0; fi
    setup_colors
    [[ -z "$PROFILE" ]] && detect_profile
    if [[ -n "$EXC_FILE" ]]; then
        load_exceptions "$EXC_FILE"
    elif [[ -f /etc/linux-audit/exceptions.conf ]]; then
        load_exceptions /etc/linux-audit/exceptions.conf
    fi

    if [[ $LIVE -eq 1 ]]; then
        printf '%slinux-audit v%s%s — auditoría de seguridad de solo lectura\n' "$C_BLD" "$VERSION" "$C_RST"
    fi

    if want_cat sys; then
        check_sys
    elif [[ -n "$EXC_WARN" ]]; then
        # Una manipulación de excepciones nunca debe pasar desapercibida
        record SYS-004 FAIL high "Archivo de excepciones inseguro" "$EXC_WARN" \
            "sudo chown root:root ARCHIVO && sudo chmod 644 ARCHIVO" "MITRE T1562"
    fi
    want_cat upd  && check_upd
    want_cat acc  && check_acc
    want_cat ssh  && check_ssh
    want_cat fs   && check_fs
    want_cat krn  && check_krn
    want_cat net  && check_net
    want_cat log  && check_log
    want_cat svc  && check_svc
    want_cat mac  && check_mac
    want_cat boot && check_boot
    want_cat cnt  && check_cnt

    compute_score
    [[ $LIVE -eq 1 ]] && summary_text "$USE_COLOR"

    if [[ -n "$OUTPUT_FILE" ]]; then
        # Escritura atómica y a prueba de carreras: mktemp crea un archivo nuevo
        # y exclusivo (permisos 600) y 'mv -T' lo renombra sin seguir enlaces
        # simbólicos que alguien pudiera crear mientras tanto.
        local tmp
        tmp=$(mktemp -- "$(dirname -- "$OUTPUT_FILE")/.linux-audit.XXXXXX") \
            || die "no se pudo crear el archivo temporal del informe"
        case "$FORMAT" in
            text) render_text > "$tmp" ;;
            json) render_json > "$tmp" ;;
            html) render_html > "$tmp" ;;
        esac
        mv -f -T -- "$tmp" "$OUTPUT_FILE" || { rm -f -- "$tmp"; die "no se pudo guardar $OUTPUT_FILE"; }
        [[ $LIVE -eq 1 ]] && printf '  Informe guardado en %s (permisos 600)\n\n' "$OUTPUT_FILE"
    else
        case "$FORMAT" in
            json) render_json ;;
            html) render_html ;;
        esac
    fi

    # Código de salida según --fail-on
    local threshold i
    threshold=$(sev_num "$FAIL_ON")
    for i in "${!R_ID[@]}"; do
        if [[ "${R_STATUS[$i]}" == FAIL ]] && [[ $(sev_num "${R_SEV[$i]}") -ge $threshold ]]; then
            exit 1
        fi
    done
    exit 0
}

# Ejecutar solo si se llama directamente (permite cargar funciones en las pruebas)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
