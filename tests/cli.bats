#!/usr/bin/env bats
# Pruebas de interfaz, formatos y garantías del script.
# Son seguras: no modifican el sistema. Se pueden correr en cualquier equipo.
#   bats tests/cli.bats

setup() {
    AUDIT="$BATS_TEST_DIRNAME/../audit.sh"
    TMP="$(mktemp -d)"
}

teardown() {
    rm -rf "$TMP"
}

# Ejecuta solo algunas categorías rápidas para que las pruebas no tarden
quick() { "$AUDIT" --no-color --only sys,acc,ssh,krn,net,mac "$@"; }

@test "--version y --help terminan con código 0" {
    run "$AUDIT" --version
    [ "$status" -eq 0 ]
    [[ "$output" == linux-audit\ v* ]]
    run "$AUDIT" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"--fail-on"* ]]
}

@test "opciones inválidas devuelven código 2" {
    run "$AUDIT" --opcion-que-no-existe;  [ "$status" -eq 2 ]
    run "$AUDIT" --format xml;            [ "$status" -eq 2 ]
    run "$AUDIT" --fail-on enorme;        [ "$status" -eq 2 ]
    run "$AUDIT" --only ssh,inventada;    [ "$status" -eq 2 ]
    run "$AUDIT" --output;                [ "$status" -eq 2 ]
    run "$AUDIT" --level 3;               [ "$status" -eq 2 ]
    run "$AUDIT" --profile laptop;        [ "$status" -eq 2 ]
    run "$AUDIT" --exceptions /no/existe; [ "$status" -eq 2 ]
}

@test "JSON es válido y tiene la estructura esperada" {
    quick --format json > "$TMP/r.json" || true
    jq -e . "$TMP/r.json" >/dev/null
    jq -e '.tool == "linux-audit" and (.score | type == "number") and .score >= 0 and .score <= 100' "$TMP/r.json"
    jq -e '.findings | length > 10' "$TMP/r.json"
    jq -e 'all(.findings[]; has("id") and has("status") and has("severity") and has("title") and has("remediation") and has("references"))' "$TMP/r.json"
    jq -e 'all(.findings[]; .status | IN("PASS","WARN","FAIL","INFO","SKIP","L2","ACCEPT"))' "$TMP/r.json"
    jq -e 'all(.findings[]; .severity | IN("critical","high","medium","low","none"))' "$TMP/r.json"
}

@test "los ID de las pruebas no se repiten" {
    "$AUDIT" --format json > "$TMP/r.json" || true
    dups=$(jq -r '.findings[].id' "$TMP/r.json" | sort | uniq -d)
    [ -z "$dups" ]
}

@test "JSON por stdout no se mezcla con texto en vivo" {
    run bash -c "'$AUDIT' --only krn --format json | jq -e .score"
    [ "$status" -eq 0 ]
}

@test "el informe HTML se genera completo y con permisos 600" {
    quick --format html -o "$TMP/r.html" >/dev/null || true
    [ -s "$TMP/r.html" ]
    grep -q '</html>' "$TMP/r.html"
    grep -q 'Confidencial' "$TMP/r.html"
    [ "$(stat -c '%a' "$TMP/r.html")" = "600" ]
}

@test "el informe de texto se guarda sin códigos de color" {
    "$AUDIT" --only krn -o "$TMP/r.txt" >/dev/null || true
    [ -s "$TMP/r.txt" ]
    ! grep -q $'\e' "$TMP/r.txt"
    [ "$(stat -c '%a' "$TMP/r.txt")" = "600" ]
}

@test "se niega a escribir sobre un enlace simbólico (ataque de symlink)" {
    echo "original" > "$TMP/victima"
    ln -s "$TMP/victima" "$TMP/enlace"
    run "$AUDIT" --only krn -o "$TMP/enlace"
    [ "$status" -eq 2 ]
    [ "$(cat "$TMP/victima")" = "original" ]
}

@test "--only ejecuta únicamente las categorías pedidas" {
    "$AUDIT" --only ssh,krn --format json > "$TMP/r.json" || true
    otros=$(jq -r '.findings[].id | select(test("^(SSH|KRN)-") | not)' "$TMP/r.json")
    [ -z "$otros" ]
}

@test "el código de salida respeta --fail-on" {
    "$AUDIT" --format json > "$TMP/r.json" || true
    criticos=$(jq '[.findings[] | select(.status=="FAIL" and .severity=="critical")] | length' "$TMP/r.json")
    run "$AUDIT" --no-color --fail-on critical
    if [ "$criticos" -gt 0 ]; then [ "$status" -eq 1 ]; else [ "$status" -eq 0 ]; fi
}

@test "funciona sin root y marca las pruebas como omitidas" {
    [ "$EUID" -eq 0 ] || skip "esta prueba necesita root para cambiar a 'nobody'"
    command -v setpriv >/dev/null || skip "falta setpriv"
    cp "$AUDIT" "$TMP/audit.sh"; chmod 755 "$TMP" "$TMP/audit.sh"
    run setpriv --reuid=65534 --regid=65534 --clear-groups "$TMP/audit.sh" --no-color --format json
    echo "$output" | jq -e '.run_as_root == false'
    echo "$output" | jq -e '[.findings[] | select(.status=="SKIP")] | length > 3'
}

@test "nunca modifica /etc ni /boot (garantía de solo lectura)" {
    [ "$EUID" -eq 0 ] || skip "solo tiene sentido como root"
    touch "$TMP/marca"; sleep 1
    "$AUDIT" --no-color >/dev/null || true
    cambios=$(find /etc /boot -xdev -newer "$TMP/marca" 2>/dev/null | head -n 5)
    echo "Archivos modificados: $cambios"
    [ -z "$cambios" ]
}

# --- Pruebas unitarias de funciones internas ----------------------------------

@test "json_esc escapa comillas, barras, saltos de línea y caracteres de control" {
    source "$AUDIT"
    out=$(json_esc $'a"b\\c\nd\te\x01f')
    [ "$out" = 'a\"b\\c\nd\tef' ]
}

@test "html_esc neutraliza HTML (evita inyección en el informe)" {
    source "$AUDIT"
    out=$(html_esc '<script>alert("x")</script> & '"'")
    [ "$out" = '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;' ]
}

@test "un nombre de archivo malicioso no rompe el JSON" {
    source "$AUDIT"
    LIVE=0
    record FS-999 FAIL high $'archivo "raro"\n</script>' 'detalle' 'fix' 'ref'
    compute_score
    render_json | jq -e '.findings[0].title | contains("</script>")'
}

# --- Reglas de justicia del informe (pruebas unitarias de record) -------------

@test "riesgo latente: con SSH apagado un fallo ALTO de SSH baja a BAJO" {
    source "$AUDIT"; LIVE=0; PROFILE=server; SSH_LATENT=1
    record SSH-001 FAIL high "root por SSH" "" "" ""
    [ "${R_SEV[0]}" = low ]
    [[ "${R_DETAIL[0]}" == *"apagado"* ]]
}

@test "nivel 2: con --level 1 un control N2 de riesgo medio pasa a recomendación" {
    source "$AUDIT"; LIVE=0; PROFILE=server; LEVEL=1
    record LOG-002 FAIL medium "auditd" "" "" ""
    [ "${R_STATUS[0]}" = L2 ]
}

@test "nivel 2: con --level 2 el mismo control sí cuenta como fallo" {
    source "$AUDIT"; LIVE=0; PROFILE=server; LEVEL=2
    record LOG-002 FAIL medium "auditd" "" "" ""
    [ "${R_STATUS[0]}" = FAIL ]
}

@test "nivel 2 con riesgo ALTO no se oculta (NOPASSWD: ALL con usuarios)" {
    source "$AUDIT"; LIVE=0; PROFILE=server; LEVEL=1
    record ACC-009 FAIL high "root sin contraseña" "" "" ""
    [ "${R_STATUS[0]}" = FAIL ]
    [[ "${R_DETAIL[0]}" == *"Nivel 2"* ]]
}

@test "perfil: servicios de escritorio son N1 en servidor y N2 en estación" {
    source "$AUDIT"; LIVE=0; LEVEL=1
    PROFILE=server;      record SVC-007 WARN low "cups" "" "" ""
    PROFILE=workstation; record SVC-007 WARN low "cups" "" "" ""
    [ "${R_STATUS[0]}" = WARN ]
    [ "${R_STATUS[1]}" = L2 ]
}

@test "los riesgos aceptados y los de Nivel 2 no restan puntos" {
    source "$AUDIT"; LIVE=0; PROFILE=server; LEVEL=1
    EXC[ACC-007]="política interna"
    record ACC-001 PASS critical "ok" "" "" ""
    record ACC-007 WARN low "caducidad" "" "" ""
    record LOG-002 FAIL medium "auditd" "" "" ""
    compute_score
    [ "${R_STATUS[1]}" = ACCEPT ]
    [ "$SCORE" -eq 100 ]
}

@test "excepciones: se cargan del archivo con su motivo" {
    printf '# comentario\nACC-007  Política corporativa: rotación cada 2 años\nbasura sin formato\n' > "$TMP/exc.conf"
    run "$AUDIT" --only acc --format json --exceptions "$TMP/exc.conf"
    echo "$output" | jq -e '.findings[] | select(.id=="ACC-007") | (.status == "ACCEPT" or .status == "PASS")'
    echo "$output" | jq -e '.exceptions_file | contains("(1)")'
}

@test "excepciones: un archivo modificable por otros se ignora y se reporta" {
    [ "$EUID" -eq 0 ] || skip "requiere root"
    printf 'ACC-001 ocultar puerta trasera\n' > "$TMP/exc.conf"
    chmod 666 "$TMP/exc.conf"
    run "$AUDIT" --only acc --format json --exceptions "$TMP/exc.conf"
    echo "$output" | jq -e '.findings[] | select(.id=="SYS-004") | .status == "FAIL"'
    echo "$output" | jq -e '[.findings[] | select(.status=="ACCEPT")] | length == 0'
}

@test "--list-checks lista todos los controles con su nivel" {
    run "$AUDIT" --list-checks
    [ "$status" -eq 0 ]
    [[ "$output" == *"| ACC-009 | N2 | N2 | CIS §5.2.4 |"* ]]
    [[ "$output" == *"| SVC-007 | N1 | N2 |"* ]]
}

@test "todo ID emitido por el script está documentado en el catálogo" {
    ids=$(grep -oE 'record "?[A-Z]+-[0-9]+' "$AUDIT" | grep -oE '[A-Z]+-[0-9]+' | sort -u)
    krn=$(grep -oE '"KRN-[0-9]+\|' "$AUDIT" | grep -oE 'KRN-[0-9]+' | sort -u)
    cat=$("$AUDIT" --list-checks | grep -oE '^\| [A-Z]+-[0-9]+' | grep -oE '[A-Z]+-[0-9]+' | sort -u)
    faltan=$(comm -23 <(printf '%s\n%s\n' "$ids" "$krn" | sort -u) <(echo "$cat"))
    echo "Sin documentar: $faltan"
    [ -z "$faltan" ]
}

@test "pkg_of atribuye binarios con rutas usr-merge (/bin vs /usr/bin)" {
    command -v dpkg-query >/dev/null || skip "sin dpkg"
    source "$AUDIT"
    [ -n "$(pkg_of "$(readlink -f "$(type -P sh)")")" ]
    [ -z "$(pkg_of /usr/local/bin/archivo-que-no-existe)" ]
}
