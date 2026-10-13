"""Backend SQLite de telemetria - Fase 4 post-BlackHat (ver
docs/roadmap.md).

Mismo contrato que JSONFileTelemetryRepository (TelemetryRepository,
M4), pero con un unico archivo .db para todas las operaciones en vez
de uno por operacion -- resuelve `list_ttps_by_operation()` (consulta
agregada cross-operacion) con una sola sentencia SQL en vez de iterar
N archivos JSON completos, el costo concreto que tenia
`apate.web._portfolio.build_portfolio()` (M13g) al construir el
heatmap del Portafolio.

Decisiones de implementacion, documentadas porque se apartan de la
letra literal del pedido:

- `sqlite3` de la stdlib, no SQLAlchemy. El proyecto ya trae
  SQLAlchemy, pero unicamente como dependencia de BUDA para sus
  propios modelos (Narrative/UserProfile/Activity) -- sumarla aca
  acoplaria apate.telemetry a esa dependencia sin necesidad real.
  sqlite3 directo mantiene la filosofia minimalista del diseño
  (seccion 1) y sigue la misma direccion que M14b/M14e (reducir
  acoplamiento con BUDA/DOLOS-T, no sumarlo).
- Sin migracion JSON -> SQLite: no hay datos reales que migrar en el
  estado actual del repo (operaciones de demo, regenerables via
  examples/seed_demo.py); construir una herramienta de migracion no
  pedida seria alcance sin necesidad.
- Conexion nueva por llamada, no una conexion persistente compartida:
  create_app() configura Flask-SocketIO con async_mode="threading"
  (M13f), y sqlite3.Connection no es segura para usarse desde threads
  distintos al que la creo con la configuracion por defecto
  (check_same_thread=True). Abrir y cerrar la conexion dentro de cada
  metodo evita tener que coordinar un pool o pasar
  check_same_thread=False (con los riesgos de correccion que eso
  implica) a cambio de una sobrecarga de conexion despreciable para el
  volumen de esta etapa (mismo criterio de "simple y suficiente" que
  ya justifica el read-modify-write completo de
  JSONFileTelemetryRepository.append()).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Union

from ..plugins.base import EventType
from .models import IoC, TelemetryRecord
from .repository import TelemetryRepository
from ..schema_version import apply_sqlite_version

_SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry_records (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    surface TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    resource_id TEXT,
    ttp_id TEXT,
    iocs_json TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telemetry_operation_id
    ON telemetry_records (operation_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_operation_ttp
    ON telemetry_records (operation_id, ttp_id);
"""


class SQLiteTelemetryRepository(TelemetryRepository):
    """Persiste todos los TelemetryRecord de todas las operaciones en
    un unico archivo SQLite. `seq` (autoincrement) preserva el orden
    de insercion para list_for_operation(), igual que el orden de
    lista de JSONFileTelemetryRepository."""

    def __init__(self, path: Union[str, Path]):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(_SCHEMA)
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(telemetry_records)").fetchall()
            }
            if "resource_id" not in columns:
                connection.execute("ALTER TABLE telemetry_records ADD COLUMN resource_id TEXT")
            # Sello de version del esquema. Los `ALTER TABLE` de arriba resuelven
            # una columna que falta, pero no pueden ver un cambio de significado
            # -- un enum renombrado, una unidad distinta -- ni decir con que
            # version se escribio esta base. Ver `apate.schema_version`.
            apply_sqlite_version(connection)
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    def append(self, record: TelemetryRecord) -> None:
        self.append_many([record])

    def append_recovered(self, record: TelemetryRecord) -> bool:
        """Recupera una proyección sin volver a publicar eventos ni ejecutar reglas."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute("SELECT 1 FROM telemetry_records WHERE operation_id=? AND source_event_id=? LIMIT 1",
                (record.operation_id, record.source_event_id)).fetchone()
            if exists:
                return False
            connection.execute("""INSERT INTO telemetry_records (id, operation_id, event_type, plugin_id, surface,
                timestamp, source_event_id, resource_id, ttp_id, iocs_json, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (record.id, record.operation_id, record.event_type.value, record.plugin_id, record.surface,
                 record.timestamp.isoformat(), record.source_event_id, record.resource_id, record.ttp_id,
                 json.dumps([ioc.to_dict() for ioc in record.iocs]), json.dumps(record.payload)))
            connection.commit()
            return True
        finally:
            connection.close()

    def page(self, operation_id: str, *, after: int = 0, limit: int = 100) -> dict:
        """Cursor de inserción, estable ante altas concurrentes y acotado."""
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("invalid_telemetry_pagination")
        connection = self._connect()
        try:
            rows = connection.execute("""SELECT seq, id, event_type, operation_id, plugin_id, surface,
                timestamp, source_event_id, resource_id, ttp_id, iocs_json, payload_json
                FROM telemetry_records WHERE operation_id=? AND seq>? ORDER BY seq LIMIT ?""",
                (operation_id, after, limit + 1)).fetchall()
        finally:
            connection.close()
        page = rows[:limit]
        return {"items": [self._row_to_record(row[1:]) for row in page],
                "next_cursor": page[-1][0] if len(rows) > limit else None}

    def append_many(self, records: list[TelemetryRecord]) -> None:
        """Persiste un lote ya normalizado en una única transacción.

        ``append()`` conserva el contrato de siempre; el seed de demo usa
        este detalle propio de SQLite para no abrir miles de conexiones al
        cargar una historia extensa. Cada fila sigue siendo exactamente el
        ``TelemetryRecord`` producido por ``TelemetryRecord.from_event()``.
        """

        if not records:
            return
        connection = self._connect()
        try:
            connection.executemany(
                """
                INSERT INTO telemetry_records (
                    id, operation_id, event_type, plugin_id, surface,
                    timestamp, source_event_id, resource_id, ttp_id, iocs_json, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        record.id,
                        record.operation_id,
                        record.event_type.value,
                        record.plugin_id,
                        record.surface,
                        record.timestamp.isoformat(),
                        record.source_event_id,
                        record.resource_id,
                        record.ttp_id,
                        json.dumps([ioc.to_dict() for ioc in record.iocs]),
                        json.dumps(record.payload),
                    )
                    for record in records
                ],
            )
            connection.commit()
        finally:
            connection.close()

    def list_for_operation(self, operation_id: str) -> list[TelemetryRecord]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT id, event_type, operation_id, plugin_id, surface,
                       timestamp, source_event_id, resource_id, ttp_id, iocs_json, payload_json
                FROM telemetry_records
                WHERE operation_id = ?
                ORDER BY seq
                """,
                (operation_id,),
            ).fetchall()
        finally:
            connection.close()
        return [self._row_to_record(row) for row in rows]

    def list_ttps_by_operation(self, operation_ids: list[str]) -> dict[str, list[str]]:
        if not operation_ids:
            return {}
        connection = self._connect()
        try:
            placeholders = ",".join("?" for _ in operation_ids)
            rows = connection.execute(
                f"""
                SELECT DISTINCT operation_id, ttp_id
                FROM telemetry_records
                WHERE operation_id IN ({placeholders}) AND ttp_id IS NOT NULL
                """,
                list(operation_ids),
            ).fetchall()
        finally:
            connection.close()

        result: dict[str, list[str]] = {}
        for operation_id, ttp_id in rows:
            result.setdefault(operation_id, []).append(ttp_id)
        for ttps in result.values():
            ttps.sort()
        return result

    def list_for_operations(self, operation_ids: list[str]) -> dict[str, list[TelemetryRecord]]:
        if not operation_ids:
            return {}
        connection = self._connect()
        try:
            placeholders = ",".join("?" for _ in operation_ids)
            rows = connection.execute(
                f"""
                SELECT id, event_type, operation_id, plugin_id, surface,
                       timestamp, source_event_id, resource_id, ttp_id, iocs_json, payload_json
                FROM telemetry_records
                WHERE operation_id IN ({placeholders})
                ORDER BY seq
                """,
                list(operation_ids),
            ).fetchall()
        finally:
            connection.close()
        result: dict[str, list[TelemetryRecord]] = {}
        for row in rows:
            record = self._row_to_record(row)
            result.setdefault(record.operation_id, []).append(record)
        return result

    @staticmethod
    def _row_to_record(row) -> TelemetryRecord:
        (
            id_,
            event_type,
            operation_id,
            plugin_id,
            surface,
            timestamp,
            source_event_id,
            resource_id,
            ttp_id,
            iocs_json,
            payload_json,
        ) = row
        return TelemetryRecord(
            id=id_,
            event_type=EventType(event_type),
            operation_id=operation_id,
            plugin_id=plugin_id,
            surface=surface,
            timestamp=datetime.fromisoformat(timestamp),
            source_event_id=source_event_id,
            resource_id=resource_id,
            ttp_id=ttp_id,
            iocs=[IoC.from_dict(d) for d in json.loads(iocs_json)],
            payload=json.loads(payload_json),
        )
