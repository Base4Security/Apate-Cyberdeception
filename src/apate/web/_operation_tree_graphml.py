"""Export GraphML (abre en Gephi) del árbol de la operación -- tercera
de la tanda de mejoras de UI/UX con referencia CounterCraft (ver
docs/roadmap.md: Deception Director exporta a Gephi). Mismo criterio
que el export STIX 2.1 del informe post-operación
(`apate.reporting.stix`): otro formato de salida sobre datos que ya
existen, sin recalcular nada -- toma el dict que ya arma
`apate.web._operation_tree.build_operation_tree()` (la misma
estructura que renderiza `operations/detail.html`), no reconstruye el
árbol.

**GraphML, sin dependencia nueva.** Es XML plano -- `xml.etree.
ElementTree` de la librería estándar alcanza, no hace falta ninguna
librería de grafos. Detalle no negociable de la especificación: cada
atributo (`<data key="...">`) tiene que declararse antes con un
`<key id="..." for="node|edge" attr.name="..." attr.type="...">` en la
raíz `<graphml>`, referenciado por ese `id` -- si no, Gephi importa el
grafo pero ignora en silencio los atributos no declarados (falla
silenciosa, no un error visible). Confirmado re-parseando el archivo
generado con `xml.etree.ElementTree` (ver
`tests/test_web_operation_tree_graphml.py`) y, de punta a punta, contra
un servidor real (ver docs/roadmap.md para el detalle de esa
verificación).

**Qué se mapea:**
- Un nodo por Operación (raíz, id `"root"` -- mismo id que ya usa
  `data-tree-id="root"` en el árbol HTML, para poder correlacionar), un
  nodo por Escenario (`anchor_id` de `build_operation_tree()` tal
  cual, incluido el bucket "Sin escenario asignado" -- nunca se
  excluye), un nodo por Capacidad/`PluginBinding` (ídem, `anchor_id` =
  `f"capability:{plugin_id}"`).
- **Recursos concretos (decoys/perfiles/honeytokens), a diferencia del
  árbol HTML: SÍ son nodos propios, un cuarto nivel real.** El árbol
  HTML los agrupa en una sola tarjeta por binding a propósito (ver
  docstring de `_operation_tree.py`: "más escaneable, sin explotar en
  decenas de nodos diminutos" en una pantalla real). Un archivo GraphML
  no tiene esa restricción de espacio, y modelarlos como nodos reales
  es justo lo que le da valor analítico a este export en una
  herramienta de grafos (conectividad a nivel de recurso, no solo la
  jerarquía de configuración) -- la razón de ser de este ítem, no un
  detalle menor.
- Aristas de jerarquía (Operación→Escenario, Escenario→Capacidad,
  Capacidad→Recurso) más las de breadcrumb (Capacidad→Capacidad vía
  `leads_to_target_anchor_id`, solo cuando resuelve -- una referencia
  rota, `leads_to_broken`, no tiene nodo destino real que apuntar; se
  omite en vez de inventar uno, mismo criterio que el árbol HTML no
  dibuja una línea para esas).

**Atributos por nodo** (declarados como `<key>`, omitidos del `<data>`
de un nodo puntual cuando no aplican -- GraphML no exige que todo nodo
tenga todos los atributos declarados): `label`, `node_type`
(`operation`/`scenario`/`capability`/`resource`), `anchor_id` (mismo id
que ya usa el árbol HTML, para correlacionar con la app), `kind`
(capacidad/recurso), `state`/`state_label` (estado en vivo, capacidad/
recurso), `detail` (texto libre corto: superficie para capacidad,
resumen de TTPs para escenario, detalle de estado para recurso),
`engage_activities` (nombres separados por coma, solo capacidad).
**Atributo por arista:** `edge_type` (`"hierarchy"`/`"breadcrumb"`).

**Media type, sin estándar IANA registrado que asumir.** GraphML no
tiene un `application/graphml+xml` registrado formalmente en IANA (a
diferencia de STIX 2.1, que sí define `application/stix+json` en su
propia especificación OASIS) -- se sirve como `application/xml`, con
el nombre de archivo terminado en `.graphml` (la extensión, no el
media type, es lo que Gephi/yEd/NetworkX usan en la práctica para
reconocer el formato)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Optional

from ..core.models import Operation
from ._operation_tree import state_label

_GRAPHML_NS = "http://graphml.graphdrawing.org/xmlns"
_XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
_SCHEMA_LOCATION = "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"

# (key id, attr.name) -- el id es lo que referencia cada <data>, el
# attr.name es lo que Gephi/yEd muestran como nombre de columna. Se
# mantienen distintos a propósito: el id tiene que ser único en todo
# el documento (nodos y aristas comparten namespace de ids en GraphML,
# aunque declaren `for` distinto), el nombre no.
_NODE_KEYS: list[tuple[str, str]] = [
    ("n_label", "label"),
    ("n_node_type", "node_type"),
    ("n_anchor_id", "anchor_id"),
    ("n_kind", "kind"),
    ("n_state", "state"),
    ("n_state_label", "state_label"),
    ("n_detail", "detail"),
    ("n_engage_activities", "engage_activities"),
]
_EDGE_KEYS: list[tuple[str, str]] = [("e_edge_type", "edge_type")]


def _add_key(graphml: ET.Element, *, key_id: str, for_: str, attr_name: str) -> None:
    key = ET.SubElement(graphml, "key")
    key.set("id", key_id)
    key.set("for", for_)
    key.set("attr.name", attr_name)
    key.set("attr.type", "string")


def _add_node(graph: ET.Element, node_id: str, attrs: dict[str, str]) -> None:
    node = ET.SubElement(graph, "node")
    node.set("id", node_id)
    for key_id, attr_name in _NODE_KEYS:
        value = attrs.get(attr_name)
        if value:
            data = ET.SubElement(node, "data")
            data.set("key", key_id)
            data.text = value


def _add_edge(graph: ET.Element, edge_id: str, source: str, target: str, edge_type: str) -> None:
    edge = ET.SubElement(graph, "edge")
    edge.set("id", edge_id)
    edge.set("source", source)
    edge.set("target", target)
    data = ET.SubElement(edge, "data")
    data.set("key", "e_edge_type")
    data.text = edge_type


def _scenario_detail(ttp_stats: Optional[dict[str, int]]) -> str:
    if not ttp_stats:
        return ""
    return (
        f"TTPs esperadas: {ttp_stats['total']} "
        f"({ttp_stats['matched']} coincidentes, {ttp_stats['not_observed']} no observadas)"
    )


def operation_tree_to_graphml(operation: Operation, tree: dict[str, Any]) -> str:
    """Serializa `build_operation_tree()` a GraphML (XML, string) --
    ver docstring del módulo para el mapeo completo. No recalcula nada
    del árbol: `tree` ya viene armado por quien llama (misma rutina que
    ya usa `operations/detail.html`)."""

    ET.register_namespace("", _GRAPHML_NS)
    ET.register_namespace("xsi", _XSI_NS)
    graphml = ET.Element(f"{{{_GRAPHML_NS}}}graphml")
    graphml.set(f"{{{_XSI_NS}}}schemaLocation", _SCHEMA_LOCATION)

    for key_id, attr_name in _NODE_KEYS:
        _add_key(graphml, key_id=key_id, for_="node", attr_name=attr_name)
    for key_id, attr_name in _EDGE_KEYS:
        _add_key(graphml, key_id=key_id, for_="edge", attr_name=attr_name)

    graph = ET.SubElement(graphml, "graph")
    graph.set("id", f"operation-{operation.id}")
    graph.set("edgedefault", "directed")

    adversary_name = operation.adversary_profile.name if operation.adversary_profile else ""
    root_detail = f"Estado: {operation.status.value}"
    if adversary_name:
        root_detail += f" · Adversario: {adversary_name}"
    _add_node(
        graph,
        "root",
        {"label": operation.name, "node_type": "operation", "anchor_id": "root", "detail": root_detail},
    )

    edge_counter = 0

    def _next_edge_id() -> str:
        nonlocal edge_counter
        edge_counter += 1
        return f"e{edge_counter}"

    # Las de breadcrumb se agregan al final, después de que todos los
    # nodos de capacidad existen -- una "lleva a" puede cruzar
    # escenarios (ver docstring de build_operation_tree()), así que su
    # destino puede no haberse creado todavía en el mismo recorrido.
    breadcrumb_edges: list[tuple[str, str]] = []

    for scenario_entry in tree["scenarios"]:
        scenario_anchor = scenario_entry["anchor_id"]
        _add_node(
            graph,
            scenario_anchor,
            {
                "label": scenario_entry["label"],
                "node_type": "scenario",
                "anchor_id": scenario_anchor,
                "detail": _scenario_detail(scenario_entry["ttp_stats"]),
            },
        )
        _add_edge(graph, _next_edge_id(), "root", scenario_anchor, "hierarchy")

        for binding_entry in scenario_entry["bindings"]:
            binding = binding_entry["binding"]
            capability_anchor = binding_entry["anchor_id"]
            _add_node(
                graph,
                capability_anchor,
                {
                    "label": binding.plugin_id,
                    "node_type": "capability",
                    "anchor_id": capability_anchor,
                    "kind": binding_entry["kind"] or "",
                    "state": binding_entry["state"],
                    "state_label": binding_entry["state_label"],
                    "detail": binding.surface or "",
                    "engage_activities": ", ".join(activity.name for activity in binding_entry["engage_activities"]),
                },
            )
            _add_edge(graph, _next_edge_id(), scenario_anchor, capability_anchor, "hierarchy")

            if binding_entry["leads_to_target_anchor_id"]:
                breadcrumb_edges.append((capability_anchor, binding_entry["leads_to_target_anchor_id"]))

            for index, resource in enumerate(binding_entry["resources"]):
                resource_id = f"{capability_anchor}:resource:{index}"
                state = resource["state"]
                _add_node(
                    graph,
                    resource_id,
                    {
                        "label": resource["label"],
                        "node_type": "resource",
                        "anchor_id": resource_id,
                        "kind": resource["kind"],
                        "state": state,
                        "state_label": state_label(state),
                        "detail": resource.get("detail") or "",
                    },
                )
                _add_edge(graph, _next_edge_id(), capability_anchor, resource_id, "hierarchy")

    for source, target in breadcrumb_edges:
        _add_edge(graph, _next_edge_id(), source, target, "breadcrumb")

    xml_bytes = ET.tostring(graphml, encoding="UTF-8", xml_declaration=True)
    return xml_bytes.decode("utf-8")
