**Apate — Guía de uso**

*Cómo operar una operación de ciberengaño de punta a punta con la aplicación real. Esta guía
complementa el [README](../README.es.md), que explica la instalación y el primer arranque. Los
ejemplos del repositorio son sintéticos y sirven para explorar la interfaz localmente.*

---

# 1. Antes de arrancar

Instalación y arranque: ver el [README](../README.es.md), sección "Probarla localmente". Con `python -m apate.web` corriendo,
la aplicación queda en `http://127.0.0.1:5000`.

## 1.1 Identificarte como operador

Hay dos modos, y la aplicación pasa de uno al otro sola:

**Sin usuarios (primer arranque).** No hay login: poné tu nombre en el campo "Operando como" del panel
lateral. Es texto libre, sin contraseña, guardado en la sesión de tu navegador. Sirve para una demo o
una red aislada.

**Con usuarios.** Apenas creás el primer usuario local, la autenticación pasa a ser global y todo
exige iniciar sesión. El primer usuario es administrador; los demás se crean desde
`/health/administration/users` o por consola:

```bash
flask --app "apate.web:create_app" create-user <nombre> --role operation --team azul
```

Hay tres roles fijos —lectura, operación y administración—, aislamiento opcional por equipo (una
operación de otro equipo devuelve 404, no una página vacía) y, si hace falta, inicio de sesión
corporativo por OIDC (ver `docs/instalacion-produccion.md`). La autorización se resuelve con una
allowlist de endpoints: una ruta nueva sin clasificar queda denegada incluso para administración.

En cualquiera de los dos modos, cada acción manual real que ejecutes sobre una capacidad (desplegar un
decoy, iniciar una narrativa, retirarla) queda atribuida en un historial de auditoría persistido, con
una cadena de hashes verificable (ver sección 3.2). Si no te identificás en el modo abierto, las
acciones se registran igual, como "sin especificar".

## 1.2 Elegir el idioma

La interfaz está en **español e inglés**. El selector "Idioma" vive en el panel lateral, dentro de
"Vista y ayuda", junto al tema y la densidad: es una preferencia tuya, no de la instalación. Si
iniciaste sesión queda guardada en tu identidad; si no, en la sesión del navegador.

Sin elegir nada, la aplicación negocia el idioma con tu navegador. Una instalación puede fijar un
idioma por defecto con `APATE_LOCALE=es|en`, y tu elección personal sigue ganando por encima de esa
variable.

Una cosa que el idioma **no** cambia, y conviene saberlo antes de mostrarle la herramienta a alguien:

- **Tus datos no se traducen.** El nombre de una operación, la descripción de un escenario, la
  narrativa o el detalle de un evento se muestran como los cargaste, en cualquier idioma. Las tres
  operaciones de ejemplo eligen idioma **al sembrarse**, no al mostrarse: `APATE_LOCALE=en python
  examples/seed_demo.py` las crea en inglés. Cambiar el selector después no reescribe una operación
  que ya existe, así que conviene decidir el idioma antes de sembrar.

Los textos propios de los informes, el kit de taller, el ensayo en seco y los mensajes de
validación del dominio usan `apate.i18n`. Los datos cargados por el operador conservan el idioma
original, también dentro de PDF y STIX.

---

# 2. Crear una operación

Desde "Operaciones" → "Nueva operación", o desde "Plantillas" si preferís arrancar de una operación
esqueleto en vez de un formulario en blanco: una plantilla **precarga el formulario, nunca crea la
operación sola** — revisás, editás y confirmás vos.

El formulario es un wizard de 3 pasos (cosmético — el envío sigue siendo un único POST al confirmar el
paso 3, no se crea nada a medio camino si abandonás el formulario):

**Paso 1 — Operación y perfil de adversario.** Nombre, objetivo, y el perfil del adversario que
esperás enfrentar: nombre del actor, motivación, activos objetivo, y las TTPs esperadas (MITRE
ATT&CK) — marcadas por checkbox desde el catálogo curado, agrupadas por táctica. Si conocés el grupo
APT real (ej. APT28, FIN7), el selector "Cargar TTPs desde grupo APT" precarga las técnicas típicas de
ese grupo (reemplaza la selección, no la suma) y sugiere motivación/notas si esos campos están vacíos
— revisalo, no lo tomes como definitivo. Si tenés un informe de CTI real (`.txt`/`.pdf`), podés
cargarlo ahí mismo: extrae candidatos de técnica/grupo por coincidencia de texto contra el catálogo
(sin IA — regex e igualdad de nombre, con falsos positivos/negativos reales posibles, especialmente si
el informe parafrasea o está en otro idioma) y los marca como sugerencia — ningún checkbox se tilda
solo, revisás y confirmás vos.

**Paso 2 — Reglas de interacción y decisiones estratégicas.** Acá vive `RulesOfEngagement`: qué
acciones están explícitamente permitidas o prohibidas (texto libre, formato `"<kind>"` o
`"<kind>:<plugin_id>"` — ver `docs/plugin-event-contract.md` sección 5.3 si vas a escribirlas a mano) y
la fecha de cierre. **Importante, y fácil de asumir mal:** estas reglas de permiso solo limitan al
motor de reglas automático (sección 4) — no bloquean lo que vos mismo hagas a mano desde el tab
"Despliegue". Es una decisión de diseño explícita (ver `docs/roadmap.md`, revisión de
seguridad post-vendorizado): las RoE acotan la automatización discrecional, no tus propias decisiones
como operador. También completás acá los objetivos estratégicos (detección temprana, recolección de
inteligencia, disuasión, atribución, validación de controles), roles/responsables, y una estimación de
recursos.

**Paso 3 — Narrativa.** El sesgo cognitivo o pretexto que la operación busca explotar (por ejemplo,
"empleado con acceso legítimo pero credenciales débiles") y su impacto psicológico esperado.

Los escenarios (paso 3 de la metodología, no confundir con este paso 3 del wizard) y las capacidades
(paso 4) se agregan **después** de crear la operación, desde el tab "Diseño" de su vista de detalle —
no en este formulario.

---

# 3. La vista de una operación: métricas y cinco tabs

Abrí cualquier operación desde `/operations/`. El encabezado —estado, transiciones válidas para ese
estado, operador, descargas si está cerrada— queda siempre visible arriba; el resto vive en cinco
tabs: **Diseño**, **Despliegue**, **Preparación y revisión**, **Mapa** y **Resultados**.

Antes de los tabs aparece el resumen operacional de esa operación: eventos persistidos, TTPs e IoCs
distintos, coincidencia esperada/observada, efectos medidos y proveedores presentes. Cada cifra indica
su fuente y período. Son conteos descriptivos; la herramienta no los convierte en un score de
efectividad.

## 3.1 Diseño (pasos 1 a 5 de la metodología)

Un solo tab con cinco secciones plegables y un índice arriba que muestra cuántas TTPs, objetivos,
escenarios y capacidades hay cargados. Se abre en "Perfil"; elegir otra sección en el índice abre esa
y cierra el resto.

**Perfil (paso 1).** Adversario, TTPs esperadas y activos objetivo. Si la operación está `ACTIVE` o
`COMPROMISED`, aparece además el panel de **perfil de adversario vivo**: TTPs observadas por telemetría
real que no estaban en tu perfil original, con casillas (ninguna premarcada) para incorporarlas sin
esperar a cerrar el ciclo. Los activos objetivo se pueden elegir del inventario (sección 8) o dejarse
como texto libre; una referencia libre se puede convertir después en ficha del inventario, y esa
conversión arrastra la cobertura ya declarada sobre esa misma referencia.

**Reglas de interacción (paso 2).** Acciones permitidas y prohibidas, restricciones legales, contacto
de escalamiento, objetivos estratégicos, roles y estimación de recursos — todo editable acá, no solo al
crear la operación. También los **criterios de cierre**: fecha, y condiciones de *gating* por evento
(el freno innegociable acordado de antemano). La semántica está escrita en la pantalla: una lista de
permitidas vacía no restringe; una no vacía bloquea todo lo que no enumera.

**Importante, y fácil de asumir mal:** estas reglas de permiso limitan al motor de reglas (sección 4),
no a lo que vos mismo hagas a mano desde "Despliegue". Es una decisión de diseño explícita: las RoE
acotan la automatización discrecional, no tus propias decisiones como operador — que quedan cubiertas
por el historial de auditoría. La misma sección lista, además, las reglas globales del motor y cuáles
son aplicables a esta operación según las capacidades vinculadas.

**Escenarios (paso 3).** Cada uno con descripción, nivel de engaño y las TTPs concretas a las que se
vincula. Si vas a correr el laboratorio con esta operación, esas TTPs se contrastan después (sección 6)
contra lo que el escenario fijo puede producir en la práctica.

**Narrativa (paso 5).** El pretexto y el sesgo cognitivo que la operación busca explotar, con sus
elementos de historia y el impacto psicológico esperado.

**Capacidades (paso 4).** Acá vinculás una capacidad a la operación — el triple Ver-Pensar-Hacer de
MITRE Engage. El formulario pide identificador, tipo (mock, honeytoken, decoy de red/host,
comportamiento simulado, canarytoken, opencanary, o el de un plugin de terceros que hayas instalado —
ver `docs/plugin-event-contract.md`), el escenario que implementa, los activos que protege, el efecto
esperado (qué va a creer el adversario, qué va a hacer, y cómo vas a saber si funcionó) y,
opcionalmente, **a qué otra capacidad lleva** — la relación de miga, que después se dibuja en el Mapa.
Debajo, colapsada, la matriz de MITRE Engage (Goals × Approaches × Activities): las actividades
sugeridas por tus TTPs esperadas o por tu objetivo estratégico aparecen etiquetadas por origen, nunca
tildadas solas.

Si elegís un tipo de decoy de red/host o de comportamiento simulado, aparecen ahí mismo los campos
para configurar el decoy o crear la narrativa: diseñar la estrategia y configurar la mecánica concreta
son un solo paso. Ninguno es obligatorio — podés vincular primero y configurar después, desde
"Despliegue".

Una vez vinculada, esta tabla también es donde **registrás el resultado medido** de cada capacidad:
qué observaste realmente contra lo que esperabas. Es lo que cierra el lazo entre "planificamos esto" y
"esto fue lo que pasó", y aparece después en el informe, en el kit de taller y en el portafolio.

## 3.2 Despliegue

Organiza cada capacidad por escenario y superficie, y es donde se opera de verdad:

- **Decoys de red/host:** crear y administrar decoys, desplegar/rotar/retirar, y start/stop/delete
  sobre un decoy concreto, con estado Docker en vivo.
- **Comportamiento simulado:** crear o vincular la narrativa, elegir o crear perfiles y actividades, e
  iniciar/detener la simulación.
- **Honeytokens:** configurar, desplegar, rotar, retirar y **comprobar acceso**. Configurar nunca crea
  archivos, desplegar es una acción separada, y nunca se sobrescribe un archivo existente. El primer
  chequeo de acceso fija el punto de referencia y lo dice explícitamente, en vez de informar un "0
  accesos" engañoso.
- **Canarytokens y OpenCanary:** configurar, desplegar, rotar, retirar y consultar actividad. El
  secreto de un canarytoken nunca vuelve al HTML; OpenCanary muestra en la propia pantalla el
  compromiso entre aislar puertos y ver la IP real del atacante.
- **Desplegar toda la campaña** en una acción, con resumen explícito: cuántas se desplegaron, cuántas
  ya lo estaban, cuántas se saltearon por falta de configuración y cuáles fallaron, con el error real
  de cada falla.

Todas estas acciones son manuales y quedan en el **historial de auditoría** con operador, fecha y
resultado, encadenadas con hashes verificables. La acción en sí no pasa por la guarda de RoE (ver
arriba), pero el evento que publica **sí** se evalúa contra las reglas globales: si una regla se
dispara, su decisión queda persistida igual que en cualquier otra vía.

Si falta Docker, WinRM o el proveedor de contenido, el recurso permanece visible con enlace a Salud y
configuración, y el estado queda como "desconocido" — nunca como "caído", que sería un dato falso.

## 3.3 Preparación y revisión

Tres cosas, antes de salir a la cancha:

- **Preparación:** cobertura de las ocho actividades estratégicas de MITRE Engage (Prepare/Understand)
  cruzadas contra los datos reales de la operación, y el contexto de comportamiento elegido. Podés
  seleccionar una fuente de la biblioteca o subir un EVTX; la extracción siempre produce un candidato
  pendiente que revisás y confirmás antes de activarlo. Una de las ocho, "Threat Model", se marca como
  *sin campo equivalente* en vez de forzar un mapeo que no existe.
- **Ensayo en seco:** recorrido determinista sobre el diseño cargado, sin desplegar ni tocar
  infraestructura. Reporta huecos estructurales —TTPs esperadas que ninguna capacidad podría observar,
  escenarios sin punto de entrada, migas rotas o en ciclo, capacidades aisladas— y distingue lo
  objetivamente roto de lo que puede ser intencional.
- **Coherencia de la ficción:** narrativa, activos, empleados ficticios, infraestructura ficticia y
  documentos señuelo en una sola vista, para juzgar si cuentan la misma historia. Los chequeos
  automáticos son heurísticas declaradas como tales, sin score: el juicio es tuyo.

## 3.4 Mapa

Tres lentes sobre la misma operación, una visible a la vez: **Estructura** (árbol operación →
escenario → capacidad → recurso concreto, con estado real por nodo y las migas dibujadas),
**Evidencia** (camino de engaño: adversario, TTPs, capacidades, eventos) y **Resumen** (relaciones en
números). Una cuarta lente, **Activos**, cruza el inventario con lo desplegado: qué activo objetivo
tiene capacidad declarada, cuál no, y qué capacidades no declaran ningún activo. Aparte, plegada, la
línea de tiempo de la operación.

El árbol se puede descargar como **GraphML** para abrirlo en una herramienta de grafos.

## 3.5 Resultados

Métricas de la operación, informes y exportaciones, heatmap de TTPs esperadas vs. observadas (estilo
ATT&CK Navigator) y línea de tiempo. Las descargas del informe aparecen cuando la operación está
cerrada (sección 11); el kit de taller está disponible en cualquier estado.

# 4. Reglas (`/rules/`)

Distinto de las reglas de interacción del paso 2 (sección 3.1): esto es el motor de decisión —
condición → acción, en YAML, evaluado en tiempo real contra los eventos que publican las capacidades.
El editor resalta sintaxis y valida en línea contra el parser real (no una copia en JavaScript)
mientras escribís, sin guardar nada inválido, y hay un **constructor visual** para armar una regla sin
escribir YAML: agrega la regla al final del documento, nunca reemplaza lo que ya escribiste.

Es determinista a propósito: no hay ningún LLM decidiendo qué desplegar. Cada regla que se dispara
queda registrada como decisión persistida, visible en el detalle de la operación y en la vista de
defensor del laboratorio, incluso después de reiniciar.

**Qué eventos evalúa.** Los que publican las capacidades al desplegarse, rotar o detectar actividad;
los que llegan por el sondeo periódico y por el puente de telemetría externa; y los que publica una
acción manual tuya. `APATE_TELEMETRY_RULES_ENABLED=False` apaga la reacción automática sobre la
telemetría autónoma sin apagar la recolección.

**Qué no ejecuta, y por qué.** Una acción que las reglas de interacción de la operación prohíben no se
ejecuta ni con la regla más específica; una acción dirigida a una capacidad no vinculada tampoco; y
hay un tope de acciones por cadena de eventos contra cascadas. Los tres casos quedan registrados como
rechazo, con **tipo estable** (`roe`, `cascade_limit`, `execution_error`), regla, capacidad objetivo y
evento disparador. Nunca falla en silencio, y un error de infraestructura no se confunde con un freno
de seguridad.

---

# 5. Telemetría (`/telemetry/`)

Elegí una operación y usá las seis vistas: **Resumen, En vivo, Eventos, IoCs, TTP observadas e
Incidentes**. Los filtros se combinan por escenario, superficie, proveedor, tipo de evento, TTP,
período, fechas y texto, se pueden guardar como vista local, se comparten por URL y permiten
exploración por *drill-down* (clic en un valor de la tabla para filtrar por él). Lo filtrado se
exporta a CSV/JSON.

"En vivo" es el buffer reciente del proceso; la etiqueta "Persistido" confirma que ese evento ya quedó
en SQLite. Reiniciar la aplicación vacía el buffer, no el historial persistido.

Encima de la telemetría hay tres capas de análisis, todas manuales y ninguna conectada al motor de
reglas:

- **Incidentes:** agrupá eventos ya observados con un nombre y notas, para estudiarlos en conjunto.
- **Clasificación TLP:** marcá un evento o un IoC con uno de los cuatro niveles. Esa marca viaja al
  bundle STIX como `marking-definition` real. Sin clasificación explícita no se asume ningún nivel.
- **Enriquecimiento de IoCs:** consulta explícita, IoC por IoC, contra un servicio externo de
  reputación (se configura en Salud). No sube artefactos: guarda solo el resumen.

La ingesta periódica consulta las capacidades vinculadas y publica por el mismo `EventBus` de la
operación. Observar actividad no dispara despliegues por sí mismo: cualquier reacción sigue dependiendo
de una regla determinista permitida por las reglas de interacción.

---

# 6. Playground (`/playground/`)

Corré una operación contra el stack real de Cyber Deception Playground (decoys reales en Docker,
tráfico de un atacante simulado). Necesita Docker instalado — ver `README.md`.

- **Vista de atacante** — las fases reales del contenedor atacante contra el escenario fijo.
- **Vista de defensor** — telemetría normalizada, decisiones y rechazos del motor de reglas en tiempo
  real (notificaciones vía WebSocket, sin recargar), y una sección "Esperado vs. observado": el heatmap
  de TTPs planificadas contra las efectivamente vistas, el plan de cada capacidad vinculada, y qué TTPs
  de cada escenario el laboratorio fijo puede o no producir en la práctica (el escenario es fijo, no
  infinitamente configurable — esta sección te lo dice explícito en vez de dejarte asumir que todo lo
  que cargaste en el paso 3 va a aparecer).

**Lanzar el atacante.** Se dispara desde la propia vista de atacante: el POST inicia una tarea de
fondo y la salida se procesa línea por línea, así que cada banner MITRE entra por el mismo bus de la
sesión y aparece en el defensor sin recargar. No es un POST síncrono — una corrida real lleva unos 18
minutos y bloquearía el pedido.

Tres límites que conviene tener presentes: hay **una sola corrida global** (el contenedor atacante es
uno solo, así que un segundo clic se rechaza aunque venga de otra operación); hace falta una sesión de
laboratorio activa; y si reiniciás la aplicación durante una corrida, el proceso queda huérfano y no
se puede recuperar ni cancelar desde la web — la propia pantalla lo advierte.

---

# 7. Portafolio (`/operations/portfolio`) y centro de impacto (`/impact/`)

**Portafolio** — métricas y cobertura agregadas entre **todas** las operaciones, no una a la vez:
eventos, IoCs y TTPs distintos, proveedores observados, efectos medidos con sus notas reales, fila
comparativa por operación, heatmap de TTPs, cobertura de Engage, capacidades por tipo y **cobertura de
activos** (cubiertos, objetivo sin cobertura, y los que no son objetivo de ninguna operación). La
pantalla explicita fuente, período y alcance, y no fabrica ningún porcentaje de efectividad.

**Centro de impacto** — pantalla completa pensada para proyector: heatmap ATT&CK, métricas y actividad
reciente sobre datos reales. `?preview=1` muestra un modo de ejemplo, rotulado como tal.

También hay una comparación descriptiva de dos operaciones (`/operations/compare`), sin scores ni
recomendaciones.

---

# 8. Inventario de activos (`/assets/`)

El paso 1 de la metodología pide "contra qué activos", y acá eso es una entidad real y global,
compartida entre operaciones: identificador, nombre, tipo, criticidad e identificador técnico
opcional. Se puede cargar a mano o importar por CSV — la previsualización valida el archivo entero
antes de escribir nada y lista fila por fila qué se acepta y qué se rechaza, con el motivo; las filas
válidas se guardan aunque otras fallen. La criticidad acepta tanto el valor interno como la etiqueta
visible.

El inventario es deliberadamente global y no se aísla por equipo: la infraestructura es compartida y
duplicarla la degradaría. Todos los roles pueden consultarlo; solo administración lo edita.

Desde una operación, los activos objetivo se eligen de este inventario, cada capacidad declara qué
activos protege, y la lente "Activos" del Mapa (sección 3.4) muestra el cruce. Hay además un
recomendador determinista —tipo de activo → capacidades aplicables— que sugiere y nada más: no crea ni
despliega.

---

# 9. Catálogo de capacidades (`/capabilities/`)

Reúne los motores registrados (los seis de fábrica más los de terceros que hayas instalado), perfiles
de identidad, tipos de actividad y fuentes de contexto reutilizables. Filtrá por tipo, superficie,
proveedor y disponibilidad. "Usar en una operación" solo abre el tab adecuado con contexto: no vincula,
marca ni despliega nada. La generación asistida de actividades produce una vista previa que copiás al
borrador y guardás en acciones separadas. Usuario y contraseña WinRM son de escritura solamente y
nunca vuelven al HTML.

Para integrar tu propia herramienta: alcanza con instalar un paquete que declare un entry point en el
grupo `apate.plugins` (contrato de control) — ver `docs/plugin-event-contract.md`. Si tu herramienta
solo se observa y no se controla, el camino es el puente de telemetría, que se configura por operación
en el tab "Diseño".

---

# 10. Salud y configuración (`/health/`)

Administra infraestructura global, no operaciones: runtime Docker para red/host, proveedor y modelo de
generación de contenido, servicio de reputación de IoCs, endpoint de SIEM/SOAR, diagnóstico de
disponibilidad y administración de usuarios locales.

Abrir una pantalla no prueba conexiones: las pruebas se ejecutan solo con un botón explícito. Las API
keys y las credenciales WinRM nunca se muestran (se escriben, no se leen) y se guardan cifradas. El
reinicio global de datos de comportamiento vive en el área avanzada y exige escribir la frase de
confirmación completa. No se puede desactivar al último administrador activo.

---

# 11. Cerrar el ciclo

Al cerrar una operación (transición a `closed`), el tab "Resultados" suma:

- **Informe post-operación** (Markdown, JSON, PDF y **STIX 2.1**) — TTPs esperadas vs. observadas vs.
  inesperadas, IoCs con su clasificación TLP, heatmap visual, y el resultado medido de cada capacidad
  (sección 3.1) lado a lado con lo planificado. El bundle STIX se puede además **enviar a un endpoint
  de SIEM/SOAR** configurado, como acción explícita.
- **Kit de taller** — material para completar con los stakeholders presentes: cada escenario con las
  preguntas Ver/Pensar/Hacer/Éxito en blanco (aunque ya tengas el efecto cargado), pensado para
  imprimir, no solo para archivar. Disponible en cualquier estado, no solo al cerrar.
- **Reoperar** — arranca una operación nueva precargada con lo aprendido: las TTPs esperadas originales
  más las observadas-e-inesperadas de esta corrida, los mismos activos objetivo. Mismo formulario de
  creación de siempre (sección 2) — revisás y confirmás, no se crea nada solo.

---

# 12. Cosas para tener presentes

- **Las reglas de interacción no cubren tus propias acciones manuales** (secciones 3.1 y 3.2) — es una
  decisión, no un bug, pero tenelo presente si estás pensando en ellas como un control de acceso. Lo
  que sí cubre tus acciones manuales es el historial de auditoría, con cadena de hashes verificable.
- **Sin usuarios, la aplicación queda abierta.** Es el modo de primer arranque, pensado para red
  aislada o local. Crear el primer usuario activa la autenticación global.
- **La extracción de CTI es matching de texto, no comprensión real** (sección 2) — revisá siempre lo
  que sugiere antes de confirmarlo.
- **El escenario del Playground es fijo** (sección 6) — no todas las TTPs que cargues en un escenario
  van a tener chance real de producirse en una corrida contra el stack incluido.
- **El cifrado de secretos protege copias y backups, no el host.** Quien puede leer el directorio de
  datos también puede leer la clave local.
- **Un solo proceso, un solo worker.** Las sesiones de laboratorio, el motor y el buffer de actividad
  viven en memoria: reiniciar los vacía, aunque el historial persistido queda.
- **Los datos ingresados por el operador conservan su idioma.** La preferencia de interfaz no traduce
  títulos, descripciones ni eventos ya guardados.
