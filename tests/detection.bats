#!/usr/bin/env bats
# Pruebas de DETECCIÓN: cada prueba siembra una vulnerabilidad real, comprueba
# que linux-audit la detecta y la deshace al terminar.
#
# ⚠️  MODIFICAN EL SISTEMA. Solo para máquinas desechables (CI, contenedores,
#     snapshots de VM). Para ejecutarlas hay que pedirlo de forma explícita:
#
#       sudo LINUX_AUDIT_DESTRUCTIVE_TESTS=1 bats tests/detection.bats

setup() {
    [ "$EUID" -eq 0 ] || skip "requiere root"
    [ "${LINUX_AUDIT_DESTRUCTIVE_TESTS:-0}" = "1" ] || skip "define LINUX_AUDIT_DESTRUCTIVE_TESTS=1 (modifica el sistema)"
    AUDIT="$BATS_TEST_DIRNAME/../audit.sh"
    TMP="$(mktemp -d)"
}

teardown() {
    [ -n "${CLEANUP:-}" ] && eval "$CLEANUP"
    [ -n "${TMP:-}" ] && rm -rf "$TMP"
    true
}

# Devuelve "ESTADO SEVERIDAD" de una prueba concreta
result_of() {
    local id=$1 cat
    cat=$(tr '[:upper:]' '[:lower:]' <<< "${id%%-*}")
    "$AUDIT" --only "$cat" --level 2 --format json 2>/dev/null \
        | jq -r --arg id "$id" '.findings[] | select(.id == $id) | "\(.status) \(.severity)"'
}

@test "ACC-001 detecta una cuenta extra con UID 0 (puerta trasera)" {
    CLEANUP="sed -i '/^backdoor:/d' /etc/passwd /etc/shadow"
    echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd
    echo 'backdoor:!:19000:0:99999:7:::' >> /etc/shadow
    [ "$(result_of ACC-001)" = "FAIL critical" ]
}

@test "ACC-003 detecta una cuenta sin contraseña" {
    CLEANUP="userdel -r sinclave 2>/dev/null"
    useradd -m sinclave
    passwd -d sinclave >/dev/null
    [ "$(result_of ACC-003)" = "FAIL critical" ]
}

@test "ACC-009 detecta sudo sin contraseña (NOPASSWD)" {
    CLEANUP="rm -f /etc/sudoers.d/zz-test"
    echo 'nobody ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-test
    chmod 440 /etc/sudoers.d/zz-test
    [ "$(result_of ACC-009)" = "FAIL high" ]
}

@test "ACC-009 no exagera: regla para un grupo sin miembros (caso Kali)" {
    CLEANUP="rm -f /etc/sudoers.d/zz-kali; groupdel zz-trusted 2>/dev/null"
    groupadd zz-trusted
    echo '%zz-trusted ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-kali
    chmod 440 /etc/sudoers.d/zz-kali
    # Solo debe quedar esta regla para que el resultado dependa de ella
    otras=$(grep -rlsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ | grep -v zz-kali || true)
    [ -z "$otras" ] || skip "el sistema ya tiene otras reglas NOPASSWD: $otras"
    [ "$(result_of ACC-009)" = "WARN low" ]
}

@test "ACC-009 regla limitada a un comando se marca como MEDIO" {
    CLEANUP="rm -f /etc/sudoers.d/zz-limit"
    echo 'nobody ALL = NOPASSWD: /usr/bin/true' > /etc/sudoers.d/zz-limit
    chmod 440 /etc/sudoers.d/zz-limit
    otras=$(grep -rlsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ | grep -v zz-limit || true)
    [ -z "$otras" ] || skip "el sistema ya tiene otras reglas NOPASSWD: $otras"
    [ "$(result_of ACC-009)" = "WARN medium" ]
}

@test "ACC-009 grupo CON miembros y NOPASSWD: ALL sigue siendo ALTO" {
    CLEANUP="rm -f /etc/sudoers.d/zz-grp; userdel zzmember 2>/dev/null; groupdel zz-admins 2>/dev/null"
    groupadd zz-admins
    useradd -G zz-admins zzmember
    echo '%zz-admins ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-grp
    chmod 440 /etc/sudoers.d/zz-grp
    [ "$(result_of ACC-009)" = "FAIL high" ]
}

@test "ACC-010 detecta un archivo sudoers modificable por todos" {
    CLEANUP="rm -f /etc/sudoers.d/zz-test2"
    echo '# vacío' > /etc/sudoers.d/zz-test2
    chmod 666 /etc/sudoers.d/zz-test2
    [ "$(result_of ACC-010)" = "FAIL critical" ]
}

@test "FS-001 detecta /etc/shadow legible por todos" {
    orig=$(stat -c '%a' /etc/shadow)
    CLEANUP="chmod $orig /etc/shadow"
    chmod 644 /etc/shadow
    [ "$(result_of FS-001)" = "FAIL critical" ]
}

@test "FS-002 detecta un script de sistema modificable por todos" {
    CLEANUP="rm -f /usr/local/bin/zz-backup.sh"
    printf '#!/bin/sh\necho ok\n' > /usr/local/bin/zz-backup.sh
    chmod 777 /usr/local/bin/zz-backup.sh
    [ "$(result_of FS-002)" = "FAIL critical" ]
}

@test "FS-004 detecta un directorio público sin sticky bit" {
    CLEANUP="rm -rf /srv/zz-publico"
    mkdir -p /srv/zz-publico
    chmod 777 /srv/zz-publico
    [ "$(result_of FS-004)" = "FAIL medium" ]
}

@test "FS-006 detecta un binario SUID peligroso (find, ver GTFOBins)" {
    CLEANUP="rm -f /usr/local/bin/find"
    cp "$(command -v find)" /usr/local/bin/find
    chmod u+s /usr/local/bin/find
    [ "$(result_of FS-006)" = "FAIL critical" ]
}

@test "FS-006 detecta un SUID peligroso escondido en /tmp o /dev/shm" {
    dir=/dev/shm; [ -d "$dir" ] && [ -w "$dir" ] || dir=/tmp
    CLEANUP="rm -f $dir/.zz-sh"
    cp "$(type -P bash)" "$dir/.zz-sh"
    chmod u+s "$dir/.zz-sh"
    run "$AUDIT" --only fs --format json
    echo "$output" | jq -e '.findings[] | select(.id=="FS-006") | .status == "FAIL" and (.detail | contains(".zz-sh"))'
}

@test "FS-006 detecta un shell SUID renombrado fuera de /tmp (por contenido)" {
    CLEANUP="rm -f /usr/local/sbin/zz-update-helper"
    cp "$(type -P bash)" /usr/local/sbin/zz-update-helper
    chmod u+s /usr/local/sbin/zz-update-helper
    run "$AUDIT" --only fs --format json
    echo "$output" | jq -e '.findings[] | select(.id=="FS-006") | .status == "FAIL" and (.detail | contains("zz-update-helper"))'
}

@test "FS-007 marca ALTO un SUID que no instaló ningún paquete" {
    CLEANUP="rm -f /usr/local/bin/zz-misterio"
    cp "$(type -P true)" /usr/local/bin/zz-misterio
    chmod u+s /usr/local/bin/zz-misterio
    [ "$(result_of FS-007)" = "FAIL high" ]
}

@test "ACC-016 detecta usuarios en el grupo shadow" {
    CLEANUP="userdel zzshadow 2>/dev/null"
    useradd -G shadow zzshadow
    [ "$(result_of ACC-016)" = "FAIL high" ]
}

@test "réplica de Kali: reglas NOPASSWD de OpenVAS y kali-trusted no son ALTO" {
    otras=$(grep -rlsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ || true)
    [ -z "$otras" ] || skip "el sistema ya tiene reglas NOPASSWD: $otras"
    CLEANUP="rm -f /etc/sudoers.d/zz-gvm /etc/sudoers.d/zz-kt; userdel _gvm 2>/dev/null; groupdel kali-trusted 2>/dev/null"
    useradd -r _gvm
    groupadd kali-trusted
    echo '_gvm ALL = NOPASSWD: /usr/sbin/openvas' > /etc/sudoers.d/zz-gvm
    echo '%kali-trusted ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-kt
    chmod 440 /etc/sudoers.d/zz-gvm /etc/sudoers.d/zz-kt
    # Con --level 2 se ve la severidad real; con --level 1 pasa a recomendación
    out=$("$AUDIT" --only acc --level 2 --format json)
    echo "$out" | jq -e '.findings[] | select(.id=="ACC-009") | .status == "WARN" and .severity == "medium" and (.detail | contains("OpenVAS")) and (.detail | contains("kali-grant-root"))'
    out=$("$AUDIT" --only acc --level 1 --format json)
    echo "$out" | jq -e '.findings[] | select(.id=="ACC-009") | .status == "L2"'
}

@test "FS-012 detecta '.' en el PATH (secuestro de comandos)" {
    run env PATH=".:$PATH" "$AUDIT" --only fs --format json
    echo "$output" | jq -e '.findings[] | select(.id=="FS-012") | .status == "FAIL"'
}

@test "SSH-001 detecta login de root con contraseña" {
    command -v sshd >/dev/null || skip "openssh-server no instalado"
    CLEANUP="rm -f /etc/ssh/sshd_config.d/00-zz-test.conf"
    mkdir -p /etc/ssh/sshd_config.d
    echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/00-zz-test.conf
    # Asegura que el directorio de configuración se incluya
    grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config || skip "sshd_config sin Include"
    [ "$(result_of SSH-001)" = "FAIL high" ]
}

@test "SSH-012 detecta authorized_keys modificable por todos" {
    CLEANUP="rm -rf /home/zzkeys; userdel zzkeys 2>/dev/null"
    useradd -m -d /home/zzkeys zzkeys
    mkdir -p /home/zzkeys/.ssh
    touch /home/zzkeys/.ssh/authorized_keys
    chmod 666 /home/zzkeys/.ssh/authorized_keys
    [ "$(result_of SSH-012)" = "FAIL high" ]
}

@test "SVC-004 marca CRÍTICO un crontab modificable por todos" {
    [ -e /etc/crontab ] || skip "sin /etc/crontab"
    orig=$(stat -c '%a' /etc/crontab)
    CLEANUP="chmod $orig /etc/crontab"
    chmod 666 /etc/crontab
    [ "$(result_of SVC-004)" = "FAIL critical" ]
}

@test "CNT-001 detecta usuarios en el grupo docker" {
    # Comprobar ANTES de programar la limpieza: nunca borrar un grupo docker real
    getent group docker >/dev/null && skip "ya existe un grupo docker real"
    CLEANUP="groupdel docker 2>/dev/null; userdel zzdock 2>/dev/null"
    useradd zzdock
    groupadd docker
    gpasswd -a zzdock docker >/dev/null
    [ "$(result_of CNT-001)" = "WARN high" ]
}

@test "el puntaje baja cuando se siembran vulnerabilidades" {
    antes=$("$AUDIT" --only fs,acc --format json | jq .score)
    CLEANUP="rm -f /usr/local/bin/find; sed -i '/^backdoor:/d' /etc/passwd"
    cp "$(command -v find)" /usr/local/bin/find && chmod u+s /usr/local/bin/find
    echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd
    despues=$("$AUDIT" --only fs,acc --format json | jq .score)
    echo "antes=$antes después=$despues"
    [ "$despues" -lt "$antes" ]
}
