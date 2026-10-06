# Política de seguridad

Apate es una herramienta de ciberengaño: se despliega **dentro** del entorno que protege, maneja
credenciales de integraciones y produce inteligencia sobre adversarios reales. Una vulnerabilidad
acá no es solo un problema del software — puede delatar una operación en curso. Por eso este
documento existe antes que la primera publicación, y no después.

## Cómo reportar

Este repositorio permanece **privado**. Los reportes internos se coordinan con sus mantenedores por
un canal privado acordado. Antes de abrirlo al público se debe habilitar un mecanismo verificable de
reporte privado en GitHub o publicar una dirección institucional de seguridad; este documento se
actualizará con el canal exacto en ese momento.

**No abras un issue público** para un problema de seguridad. Un issue es visible desde el momento en
que se crea, y en una herramienta que corre dentro de la red de alguien eso convierte un reporte en
un aviso al adversario.

Ayuda incluir, en la medida en que lo tengas:

- Versión afectada (`/about` la muestra, junto con la revisión exacta), y cómo la desplegaste.
  Si el problema es de una dependencia, `/about/sbom.json` —con sesión iniciada— da el
  inventario completo con las versiones instaladas, en CycloneDX.
- Qué permite hacer el problema, no solo qué está mal. Una ruta sin clasificar en la allowlist de
  `apate/web/access.py` y una fuga de credenciales de integración no son lo mismo.
- Los pasos para reproducirlo, o el fragmento de código donde lo viste.
- Si ya lo estás explotando en un entorno propio, decilo: cambia la urgencia.

## Qué esperar

Este es un proyecto con un equipo chico. Los plazos siguientes son objetivos para el futuro canal de
reporte; no constituyen un SLA hasta que ese canal esté habilitado:

| | |
|---|---|
| Acuse de recibo | Dentro de los **5 días hábiles** |
| Primera evaluación (si aplica, y qué gravedad tiene) | Dentro de los **15 días hábiles** |
| Divulgación | Coordinada con quien reportó, después de que exista la corrección |

Si no hay respuesta, insistí por el mismo canal privado.

## Alcance

**Entra en alcance** el código propio de este repositorio: `src/apate/` —el modelo de operaciones,
el motor de reglas, las capacidades de engaño, la telemetría, los informes, la interfaz web, la
identidad y el control de acceso, la auditoría y el cifrado de secretos— y sus dependencias tal como
las declara [`NOTICE`](NOTICE).

**Tiene tratamiento aparte** el código vendorizado bajo `src/DOLOST/`, `src/BUDA/` y
`playground-stack/`. Son copias congeladas de otros proyectos (ver "Atribución" en el
[`README.md`](README.md)); reportalas igual por este canal, y se coordina con el origen que
corresponda.

**No entra en alcance**, y conviene decirlo para no hacerte perder el tiempo:

- **Las credenciales de ejemplo del laboratorio.** `playground-stack/frontend/config/` contiene
  archivos que *parecen* secretos filtrados —`aws-credentials.json`, un `environment.env` que dice
  "CRITICAL: This file contains production secrets"— y lo parecen **a propósito**: son los señuelos
  que el ejercicio de engaño expone para que un atacante los encuentre. La clave de AWS es
  `AKIAIOSFODNN7EXAMPLE`, la que la propia documentación de AWS usa como ejemplo, y no da acceso a
  nada. El escaneo de secretos de GitHub va a marcarlos; no son un hallazgo.
- **La instancia sin usuarios creados.** Apate arranca en modo abierto hasta que se crea la primera
  identidad, y lo dice en pantalla. Es una decisión de producto para el primer arranque, no un
  control faltante.
- **Una instalación sin `APATE_SOURCE_URL`.** `/about` declara explícitamente que la instalación no
  informó dónde está su fuente. Es la respuesta correcta a una configuración incompleta, no una
  omisión.
- **Que `/about/sbom.json` exija sesión.** Es deliberado: el aviso de licencia que obliga la
  AGPLv3 es público, pero el inventario de versiones instaladas es un mapa de superficie de ataque
  y esta herramienta corre dentro de la red que protege. Quien necesite el SBOM sin tener cuenta lo
  recibe fuera de banda, generado en el build.
- **Un único proceso y un único worker.** La instalación soportada es `--workers 1`
  (ver [`docs/instalacion-produccion.md`](docs/instalacion-produccion.md)); que con más workers se
  rompan las notificaciones en vivo es una limitación declarada de arquitectura, no un defecto de
  seguridad.

## Versiones soportadas

| Versión | Estado |
|---|---|
| `0.1.x` | En desarrollo, sin publicación pública todavía. Las correcciones van sobre la rama principal. |

No hay todavía una política de backport, porque no hay todavía una versión publicada a la que
volver. Cuando exista la primera, esta tabla la nombra.

## Lo que el propio proyecto ya declara como limitación

Reportar algo que ya está documentado como fuera de alcance no ayuda a nadie, así que acá está la
lista corta:

- **La cadena de hashes de la auditoría detecta una edición aislada o un borrado, pero no a un
  escritor que reconstruya todos los hashes posteriores.** Cerrarlo requiere firma con clave externa
  o un registro append-only externo, y está identificado como capacidad de la edición comercial
  (ver el límite entre ediciones en [`README.md`](README.md)).
- **El cifrado de secretos protege copias, backups y JSON compartidos, no a quien tenga acceso al
  host**, porque esa misma persona puede leer la clave local. La custodia externa (Vault/KMS) es lo
  que cierra ese hueco (ídem, 2.4).

Si encontrás una forma de superar esas limitaciones **más allá de lo que dicen** —por ejemplo,
alterar la auditoría sin acceso de escritura al host— eso sí es un hallazgo, y de los buenos.
