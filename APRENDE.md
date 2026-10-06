# Aprende con este proyecto

Guía para entender `audit.sh` y practicar en tu Kali (VirtualBox). Ve parte por parte; no hace falta entender todo el primer día.

## 1. Antes de empezar: toma un snapshot

En VirtualBox: **Máquina → Tomar instantánea**. Si algo sale mal mientras practicas, vuelves a ese punto en segundos. Es lo que hacen los profesionales antes de tocar un sistema.

## 2. Correrlo

```bash
cd ~/linux-audit
chmod +x audit.sh
sudo ./audit.sh                         # en la terminal
sudo ./audit.sh -f html -o informe.html # informe para abrir en Firefox
firefox informe.html
```

En Kali vas a ver bastantes fallos: es normal. Kali está hecha para atacar, no para ser un servidor seguro (sin firewall, sin auditd, etc.). Eso la convierte en un buen laboratorio: puedes corregir cosas y ver cómo sube el puntaje.

## 3. Cómo leer el informe (niveles, perfiles y excepciones)

- **[FALLO] / [AVISO]**: problemas a corregir, ordenados por severidad.
- **[NIVEL 2]**: recomendaciones de defensa en profundidad del CIS. Son opcionales y no restan puntos. Para exigirlas, usa `--level 2`.
- **[ACEPTADO]**: riesgos que decidiste asumir y documentaste en el archivo de excepciones (ver `docs/exceptions.example.conf`).
- **Perfil**: si tu equipo tiene entorno gráfico (como Kali), se audita como **estación de trabajo**. Un servidor se audita más estricto.

En tu Kali vas a ver cosas que son normales para una distro de pentest: clientes telnet/ftp (SVC-006), la regla `sudo` de OpenVAS (ACC-009) o `ptrace_scope = 0` para depuradores (KRN-007). El informe te explica el contexto de cada una. Un buen auditor no "arregla" todo: decide y documenta.

Para ver de dónde sale cada control:
```bash
./audit.sh --list-checks
```

## 4. Cómo está organizado el código

En orden de aparición en `audit.sh` (búscalas con `grep -n 'NOMBRE' audit.sh`):

| Parte | Qué hace |
|-------|----------|
| Endurecimiento (inicio) | Fija `PATH`, `LC_ALL` y `umask` para que el script sea seguro aunque lo corra root |
| `META` | **Catálogo:** nivel CIS (servidor/estación) y referencia de cada control |
| `record` | **La función central.** Cada prueba llama a `record ID ESTADO SEVERIDAD ...`; aquí se aplican nivel, riesgo latente y excepciones |
| `check_*` | Una función por categoría (`check_ssh`, `check_fs`…) |
| `compute_score` | Calcula el puntaje ponderado |
| `render_text/json/html` | Generan los informes a partir de los resultados guardados |
| `main` (final) | Lee las opciones y llama a todo en orden |

Idea clave de diseño: **las pruebas no imprimen directamente**, guardan resultados con `record`. Gracias a eso, el mismo resultado sirve para texto, JSON y HTML. Así se separan los datos de la presentación.

## 5. Practica: rompe y detecta

Haz esto **solo en tu VM** y deshaz cada cambio:

```bash
# Puerta trasera: un segundo usuario con UID 0
echo 'test0:x:0:0::/root:/bin/bash' | sudo tee -a /etc/passwd
sudo ./audit.sh --only acc | grep ACC-001
sudo sed -i '/^test0:/d' /etc/passwd        # deshacer

# SUID peligroso: 'find' con SUID permite volverse root
sudo cp /usr/bin/find /tmp/find && sudo chmod u+s /tmp/find
sudo ./audit.sh --only fs | grep FS-006     # ¿lo detecta? (pista: /tmp es local)
sudo rm /tmp/find                            # deshacer

# Corregir de verdad: activa el firewall y mira cómo cambia NET-002
sudo apt install ufw && sudo ufw enable
sudo ./audit.sh --only net
```

Para entender por qué un SUID en `find` es tan grave, busca `find` en https://gtfobins.github.io.

## 6. Conceptos de Bash que aparecen

| Concepto | Ejemplo en el script | Para qué |
|----------|---------------------|----------|
| Arreglos | `R_ID+=("$id")` | Guardar resultados |
| Arreglo asociativo | `declare -A N_SEV` | Contar por severidad |
| Aritmética octal | `(( 8#$perm & 8#022 ))` | Comparar permisos bit a bit |
| Here-string | `grep x <<< "$var"` | Pasar una variable como entrada |
| Sustitución de procesos | `<(...)` | Usar la salida de un comando como archivo |
| `find -printf` | `-printf 'SUID\t%p\n'` | Un solo recorrido del disco para varias pruebas |
| `IFS='\|' read -r` | reglas del kernel | Separar campos de un texto |
| Guarda de `source` | `[[ "${BASH_SOURCE[0]}" == "$0" ]]` | Poder cargar funciones en las pruebas |

## 7. Preguntas de entrevista que este proyecto te prepara para responder

- ¿Por qué un usuario extra con UID 0 es señal de compromiso?
- ¿Qué es un binario SUID y cómo se usa para escalar privilegios?
- ¿Por qué deshabilitar el login por contraseña en SSH?
- ¿Para qué sirve auditd y por qué importa la sincronización de hora en un incidente?
- ¿Qué diferencia hay entre CIS Nivel 1 y Nivel 2? ¿Por qué no se aplica todo siempre?
- ¿Por qué un riesgo aceptado debe quedar documentado, y quién debería aprobarlo?
- ¿Qué es CIS Controls y qué es MITRE ATT&CK? ¿En qué se diferencian? (CIS dice *qué proteger*; ATT&CK describe *cómo atacan*.)
- ¿Por qué un script que corre como root debe fijar su propio `PATH`?

## 8. Retos (cada uno es un buen commit)

1. **Fácil:** agrega a `check_krn` la regla `net.ipv4.conf.default.accept_redirects = 0` (copia una línea del arreglo `rules`).
2. **Fácil:** agrega `nmap` a la lista de SUID peligrosos si no está, y verifica con una prueba.
3. **Medio:** nueva prueba `ACC-013`: avisa si alguna cuenta humana no ha iniciado sesión en 90 días (pista: `lastlog -b 90`).
4. **Medio:** crea tu archivo de excepciones para Kali con 2 o 3 riesgos que decidas aceptar, cada uno con su motivo.
5. **Medio:** escribe una prueba Bats en `tests/detection.bats` para la regla que agregaste.
6. **Difícil:** opción `--diff anterior.json` que muestre qué mejoró y qué empeoró desde la última auditoría.

Antes de cada commit corre `shellcheck audit.sh` y `bats tests/cli.bats`.

## 9. Subirlo a GitHub

```bash
cd ~/linux-audit
git init
git add .
git commit -m "linux-audit v2.0.0: auditoría mapeada a CIS v8 y MITRE ATT&CK"
git branch -M main
git remote add origin https://github.com/drewagaiin/linux-audit.git
git push -u origin main
```

Luego reemplaza `drewagaiin` en `README.md` y `TU_NOMBRE` en `LICENSE`. En la pestaña **Actions** verás el CI probando tu código en Kali, Debian y Ubuntu.
