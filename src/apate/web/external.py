"""DOLOS-T y BUDA como librerias puras dentro del proceso de APATE
(M14b/M14e) - documento de diseno, seccion 4.5: "APATE, DOLOS-T y BUDA
se ejecutan como un unico proceso".

**M14b -- `mount_dolost()` dejo de registrar cualquier blueprint Flask
de DOLOS-T. M14e -- `mount_buda()` hace lo mismo con los nueve
blueprints de BUDA.** Hasta M8c, ambas funciones montaban las
aplicaciones web reales de cada herramienta bajo `/dolost`/`/buda`. El
inventario de M14a (DOLOS-T) y M14c (BUDA) -- ver docs/roadmap.md
seccion M14 -- encontraron en los dos casos que esas rutas o bien
quedaban redundantes con `Operation` o bien ya tenian equivalente
nativo en los blueprints funcionales de Operaciones, Catálogo, Salud y Telemetría, con los últimos
gaps reales cerrados en cada hito (decoys puntuales para DOLOS-T en
M14b; CRUD de `UserProfile`/generacion asistida por LLM para BUDA en
M14d/M14e). `/dolost/...` y `/buda/...` dejan los dos de responder por
completo, sin paso de migracion.

Con esto, **los dos problemas de integracion que el diseno original no
anticipaba en detalle quedan resueltos de raiz, no solo mitigados**:

1. **Templates.** Hasta M14e, ninguno de los blueprints de DOLOS-T/BUDA
   se construyo con `template_folder=` explicito, asi que
   `render_template()` dentro de sus vistas resolvia por defecto contra
   el `Flask(__name__)` de *quien los registraba* -- la app de APATE,
   no la carpeta `templates/` real de cada paquete. Como APATE, DOLOS-T
   y BUDA tienen los tres un `base.html` con el mismo nombre, eso
   colisionaba (`DispatchingJinjaLoader` prioriza siempre el loader de
   la app antes que el de cualquier blueprint, sin importar cual esta
   manejando el request). Se resolvio hasta M14d con un
   `jinja2.BaseLoader` propio (`_BlueprintAwareLoader`, retirado en
   M14e) que miraba `flask.request.blueprint` para decidir que carpeta
   de templates priorizar. **Con ningun blueprint de ninguna de las dos
   herramientas registrado, la colision es estructuralmente imposible**
   (no hay ningun `render_template()` ajeno compitiendo por el nombre
   `base.html`) -- `_BlueprintAwareLoader`/`install_blueprint_aware_loader()`
   se retiraron enteros en M14e en vez de dejarlos sin uso: no
   quedaba ningun `template_dirs_by_blueprint` real que pudieran
   recibir.

2. **Assets estaticos.** Por la misma razon, ninguna plantilla de
   DOLOS-T/BUDA se sirve ya dentro del proceso de APATE, asi que
   ninguna pide sus assets propios (`url_for('static', ...)` contra
   `css/style.css`/`images/logo.png`/`js/scripts.js` de BUDA, el unico
   caso real que `mount_buda()` todavia alimentaba hasta M14d) --
   confirmado con un grep de las plantillas propias de APATE antes de
   retirarlo, ninguna las referencia. La ruta `/static/<path:filename>`
   de `create_app()` sigue existiendo (assets propios de APATE), pero
   ya no necesita ningun directorio aportado por herramienta externa.

Caso particular de la seccion 4.5 del diseno, **actualizado en M13f**:
DOLOS-T usa Flask-SocketIO (`blueprints/websocket.py`) para su vista de
actividad en tiempo real, atado en su propio `main()` a una instancia
de `SocketIO` construida sobre su propia app (nunca levantada en este
escenario). El "patron socketio = SocketIO() a nivel de modulo +
socketio.init_app(app)" no es lo que el codigo real usa (verificado, no
asumido) -- `main()` hace `socketio = SocketIO(app, ...)` en una sola
linea, atado directamente a su propia app local. No hay ninguna
instancia reutilizable para "inicializar sobre la app de APATE".

**Hasta M13f, `mount_dolost()` era el UNICO lugar que creaba esa
instancia** -- y solo se llamaba con `APATE_MOUNT_EXTERNAL_TOOLS=True`
(la mayoria de la suite de tests corre con el flag en `False`, ver
`tests/conftest.py`), asi que cualquier notificacion propia de APATE
(no de DOLOS-T) no tenia forma de asumir que existiera un `SocketIO`
real. **M13f desacopla la instancia de esta funcion**: `create_app()`
(`apate.web`) la crea de forma incondicional, sin depender de
`APATE_MOUNT_EXTERNAL_TOOLS` ni de que `DOLOST` este instalado
(`flask-socketio` es dependencia de `apate` desde M8c, esto no suma
una dependencia nueva) -- `mount_dolost()` la RECIBE como parametro en
vez de crearla, y sobre ella hace lo que ya hacia: registrar el mismo
`WebSocketNamespace('/')` que DOLOS-T ya define (la clase se reutiliza
tal cual, solo cambia sobre que instancia corre), mas
`DolostLogger.get_instance(socketio=socketio)`/
`DockerManager.get_instance()` -- **esto si sigue gateado por
`APATE_MOUNT_EXTERNAL_TOOLS`** (via el `if` en `create_app()`, no
tocado aca), porque si depende del paquete `DOLOST` instalado, a
diferencia de la instancia de `SocketIO` en si. El frontend
(`view_activities_worker.js`, `view_operations_worker.js`) conecta via
`io.connect(location.protocol + '//' + document.domain + ':' + location.port)`
-- mismo origen que la pagina, sin namespace/puerto fijo -- asi que
funciona sin cambios corriendo dentro del proceso de APATE.
"""

from __future__ import annotations

from typing import Optional

from flask import Flask
from flask_socketio import SocketIO


def mount_dolost(app: Flask, socketio: SocketIO) -> SocketIO:
    """**M14b -- ya NO registra los blueprints Flask de DOLOS-T**
    (`api_blueprint`/`views_blueprint`, montados hasta M8c bajo
    `/dolost`): el inventario de M14a confirmó que sus rutas o bien
    quedaban redundantes con `Operation` (la UI/API de
    `operationsdb.json` -- confirmado con el usuario que nunca se usó
    en la demo real, sin datos que migrar) o bien ya tenían equivalente
    nativo en `apate.web.blueprints.operations`/`telemetry`/`health` (paneles
    "Decoys DOLOS-T" de M11 fase 1, Telemetría y configuración de runtime,
    más las rutas de `start`/`stop`/`delete` de decoy que M14b agrega
    para cerrar los últimos gaps reales). `/dolost/...` deja de
    responder por completo.

    **M13f -- ya NO crea la instancia de `SocketIO`, la recibe.** Hasta
    M13f era la única dueña de `SocketIO(app, ...)`; ahora `create_app()`
    la crea de forma incondicional (ver docstring del módulo) y la pasa
    acá. Lo que esta función sigue haciendo sobre ella, porque APATE sí
    lo necesita como *librería* (no como app web): le registra el
    `WebSocketNamespace` de DOLOS-T -- lo sigue usando
    Telemetría en vivo y el panel nativo de decoys (stats en vivo por
    contenedor, M14b) -- y fuerza la instanciación
    temprana de `DockerManager`. Devuelve la misma instancia recibida,
    sin crear una segunda, por si el caller la necesita directo."""

    from DOLOST.blueprints.websocket import WebSocketNamespace
    from DOLOST.services.docker_manager import DockerManager
    from DOLOST.services.logger import DolostLogger

    socketio.on_namespace(WebSocketNamespace("/"))

    # DolostLogger es un singleton (services/logger.py): si algun codigo
    # de DOLOS-T ya montado (blueprints, DockerManager) llama a
    # logger.info(..., ws=True) antes de esto, va a emitir sobre un
    # socketio no configurado (mensaje de advertencia por consola, no un
    # error) -- se inicializa aca, apenas se registra el namespace, para
    # minimizar esa ventana.
    DolostLogger.get_instance(socketio=socketio)
    DockerManager.get_instance()

    return socketio


def _agregar_columna_de_comandos(buda_db) -> None:
    """Agrega `activities.commands` a una base que se creo sin esa columna.

    `create_all()` crea tablas que faltan, pero **no** agrega una columna a una
    tabla que ya existe: sin esto, una instalacion anterior arranca bien y
    revienta al leer el repertorio aprobado. Mismo patron y mismo criterio que
    los `ALTER TABLE` de `apate.rules.repository` y
    `apate.telemetry.sqlite_repository`: se consulta la forma real de la tabla
    en vez de asumirla, y agregar una columna nullable no toca ningun dato.
    """

    from sqlalchemy import inspect, text

    inspector = inspect(buda_db.engine)
    if "activities" not in inspector.get_table_names():
        return
    columnas = {columna["name"] for columna in inspector.get_columns("activities")}
    if "commands" in columnas:
        return
    buda_db.session.execute(text("ALTER TABLE activities ADD COLUMN commands TEXT"))
    buda_db.session.commit()


def mount_buda(app: Flask, *, database_uri: Optional[str] = None) -> None:
    """**M14e -- ya NO registra los nueve blueprints Flask de BUDA**
    (`root_bp`/`context_bp`/`narratives_bp`/`user_profiles_bp`/
    `activities_bp`/`narrative_review_bp`/`statistics_bp`/`ai_bp`/
    `settings_bp`, montados hasta M14d bajo `/buda`): el inventario de
    M14c confirmo que su UI/API quedaban o bien redundantes con
    `Operation` o bien con equivalente nativo en
    `apate.web.blueprints.plugins`/`health`/`operations` (paneles "Narrativa BUDA"
    de M11 fase 1, Catálogo y Salud, más el CRUD de
    `UserProfile` que M14d agrega para cerrar el gap mas grande que
    quedaba) -- con la generacion asistida por LLM de
    `/capabilities/behavior-activities` (único consumidor real de `ai_bp` que
    quedaba, ver M14e) pasando a llamar directo a
    `BUDA.routes.ai_integration.generate_activity()` en vez de a
    `/buda/ai/generate/activitytype` por HTTP interno.
    `/buda/...` deja de responder por completo.

    Lo que sigue haciendo, porque APATE si lo necesita como *libreria*
    (no como app web): ata la `db` de BUDA (Flask-SQLAlchemy,
    completamente separada de la persistencia JSON del resto de APATE)
    a la app de APATE -- mismo `db.create_all()` + reset de
    `Narrative.is_running` que hace `BUDA.app.main()` al arrancar de
    forma standalone. La usan `BudaPlugin` y los paneles nativos de
    M11/M14d, ninguno de los cuales dependia de ningun blueprint -- ya
    llamaban directo a modelos/funciones de BUDA."""

    from BUDA.app import db as buda_db
    from BUDA.models.narrative import Narrative

    # setdefault, no set directo: si quien llama a create_app() ya paso
    # un SQLALCHEMY_DATABASE_URI propio (por ejemplo, un test apuntando
    # a un sqlite temporal), no lo pisa.
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", database_uri or "sqlite:///buda.db")
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    buda_db.init_app(app)

    with app.app_context():
        buda_db.create_all()
        _agregar_columna_de_comandos(buda_db)
        buda_db.session.query(Narrative).update({Narrative.is_running: False})
        buda_db.session.commit()
