# Política de seguridad

## Reportar una vulnerabilidad

Si encuentras un problema de seguridad **en linux-audit** (por ejemplo, una forma de que el script modifique el sistema, ejecute código no previsto o filtre información sensible), no abras un issue público.

Usa la opción **"Report a vulnerability"** de la pestaña *Security* de este repositorio (GitHub Private Vulnerability Reporting). Incluye:

- Versión (`./audit.sh --version`) y distribución.
- Pasos para reproducirlo.
- Impacto estimado.

Respuesta inicial en un máximo de 7 días.

## Garantías de diseño

1. **Solo lectura:** el script nunca modifica el sistema auditado. Una prueba automatizada verifica que no cambie nada en `/etc` ni `/boot`.
2. **Sin red:** no realiza conexiones de red.
3. **Sin secretos en la salida:** nunca imprime hashes de contraseñas ni contenido de llaves privadas.
4. **Informes protegidos:** se crean con permisos `600` y se rechazan rutas de salida que sean enlaces simbólicos.
