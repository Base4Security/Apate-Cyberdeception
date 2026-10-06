# Apate

**Orquestación abierta de ciberengaño centrada en la operación.**

[English](README.md)

Apate permite diseñar una operación de engaño, vincular señuelos y comportamientos de identidad simulados, observar interacciones, aplicar reglas deterministas dentro de las reglas de interacción y revisar la evidencia. Su consola está disponible en español e inglés. Ningún LLM autoriza ni decide despliegues.

Este repositorio contiene la **edición comunitaria completa**. [Parallax Deception](https://parallaxdeception.com/) es el producto comercial previsto sobre Apate. Sus módulos empresariales se desarrollan en un paquete privado separado; Apate no tiene límites artificiales ni un bloqueo por licencia.

## Capacidades

| Área | Incluido en Apate |
| --- | --- |
| Operaciones | Perfil de adversario, escenarios, narrativa, reglas de interacción, ciclo de vida, plantillas, portafolio e historial. |
| Engaño | Capacidades mock y honeytoken, integraciones con DOLOS-T, BUDA, Canarytokens, OpenCanary y Cyber Deception Playground; descubrimiento de plugins de terceros. |
| Decisión | Reglas YAML condición/acción, evaluación determinista, límites de alcance, guardas de RoE y registro de rechazos. |
| Observación | Telemetría normalizada, TTP e indicadores, incidentes, clasificación TLP, bandeja SOC y puente de telemetría externa. |
| Gobierno básico | Identidades locales, roles fijos, aislamiento por equipo, OIDC opcional, auditoría, planes aprobados, límites de ejecución y cifrado local de secretos. |
| Análisis y salida | Catálogos ATT&CK y Engage, extracción CTI, cobertura de activos, ensayos en seco, informes, PDF, STIX 2.1, GraphML y exportación genérica a SIEM/SOAR. |

La [guía de uso](docs/guia-de-uso.md) explica el recorrido real de la consola. También están la [arquitectura](docs/architecture.md), el [contrato de plugins y eventos](docs/plugin-event-contract.md) y la [instalación de producción](docs/instalacion-produccion.md).

## La consola

Estas son capturas de la **GUI real de Apate en inglés**, tomadas localmente con las operaciones sintéticas incluidas. No son mockups ni imágenes de Parallax. Los conteos de telemetría proceden de datos generados para pruebas, no de un despliegue de campo.

**Operaciones y estado actual**

![Tablero de operaciones de Apate con tres operaciones sintéticas](docs/assets/operations.png)

**Estado, evidencia y próxima acción de una operación**

![Detalle de una operación sintética de Apate](docs/assets/operation-detail.png)

**Capacidades de engaño disponibles**

![Catálogo de capacidades de Apate](docs/assets/capabilities.png)

**Telemetría y evidencia**

![Detalle de telemetría de Apate con eventos, indicadores y TTP sintéticos](docs/assets/telemetry.png)

## Probarla localmente

Requiere Python 3.10 o superior. El primer arranque local no necesita AD, SIEM, IdP ni Docker; cada integración externa requiere sus propios prerrequisitos.

```bash
git clone https://github.com/fedequark/Apate-Cyberdeception.git
cd Apate-Cyberdeception
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m apate.web
```

Abrí [http://127.0.0.1:5000](http://127.0.0.1:5000). El servidor de desarrollo escucha en loopback. Sin usuarios locales, el primer arranque queda abierto para configuración y demostraciones; creá un administrador antes de exponerlo a otras personas. Los datos se guardan por defecto en `.apate_data/`, ignorado por Git.

Para cargar **tres operaciones sintéticas** en una instalación local descartable, detené el servidor y ejecutá `python examples/seed_demo.py` antes de volver a iniciarlo. La variable `APATE_LOCALE=en` siembra los ejemplos en inglés. El selector de idioma traduce la interfaz, pero no el contenido de las operaciones ya guardadas.

La suite corre con `python -m pytest`. Las pruebas locales cubren contratos y flujos sintéticos; los gates reales de AD/SMB, Vault, IdP, SIEM, Docker y evaluación con operadores siguen pendientes de infraestructura externa.

## Ediciones y licencia

Apate conserva la aplicación comunitaria, incluida su GUI, integraciones, telemetría, informes y gobierno básico. Parallax está previsto para agregar políticas organizacionales, aprovisionamiento de directorio, ingesta y entrega corporativa y auditoría anclada externamente mediante módulos separados. Esos módulos siguen en desarrollo local; este corte no afirma que estén listos para producción. Una licencia comercial también podría ofrecer términos distintos de uso para Apate. El código comunitario se distribuye bajo **AGPL-3.0-or-later**; ver [LICENSE](LICENSE), [NOTICE](NOTICE) y [CONTRIBUTING.md](CONTRIBUTING.md).

DOLOS-T y BUDA conservan atribución y licencia en `src/DOLOST/` y `src/BUDA/`. El stack Cyber Deception Playground conserva su licencia en `playground-stack/`.

## Estado

Es una candidata bajo verificación local. No se declara eficacia de campo, alta disponibilidad productiva ni pruebas completas contra infraestructura externa. Revisá los [gates de versión](docs/release-gates.md) y [SECURITY.md](SECURITY.md) antes de desplegar.
