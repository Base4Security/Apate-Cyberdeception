# Apate Core

[English](README.md) · Español

**Una base abierta y ejecutable para operaciones de ciberengaño centradas en la operación.**

Apate Core reúne un modelo de operación, reglas deterministas, un contrato de plugins y telemetría básica. El plugin incluido es **simulado**: permite probar el flujo completo en una máquina local sin desplegar señuelos reales ni conectarse a infraestructura externa. La versión actual es `0.1.0a1` (alfa).

## Verlo funcionar

Esta captura reproduce la salida **real** de `python examples/quickstart.py`. El identificador de operación cambia en cada ejecución. La TTP `T1078` es una observación sintética, no evidencia de un ataque real.

![Salida de terminal de una ejecución real del ejemplo](docs/assets/quickstart.png)

## Instalación y primer uso

Requiere Git y Python 3.10 o superior. La instalación descarga dependencias de Python; el ejemplo no necesita red, cuentas, credenciales, contenedores ni laboratorio.

**macOS / Linux**

```bash
git clone https://github.com/fedequark/Apate-Cyberdeception.git
cd Apate-Cyberdeception
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python examples/quickstart.py
python -m pytest -q
```

**Windows PowerShell**

```powershell
git clone https://github.com/fedequark/Apate-Cyberdeception.git
Set-Location Apate-Cyberdeception
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe examples/quickstart.py
.\.venv\Scripts\python.exe -m pytest -q
```

La ejecución crea `.apate_data/operations/<operation-id>.json` y `.apate_data/telemetry/<operation-id>.json`. Cada nueva ejecución genera otra operación. `.apate_data/` está excluido de Git.

![Salida de terminal de la suite de pruebas](docs/assets/tests.png)

La captura corresponde a 92 pruebas locales aprobadas. La [CI](https://github.com/fedequark/Apate-Cyberdeception/actions/workflows/tests.yml) ejecuta las pruebas y el ejemplo en Windows y Ubuntu con Python 3.10 y 3.12; consultá allí el resultado del commit más reciente.

## Qué incluye

| Componente | Uso actual |
| --- | --- |
| Operación | Perfil de adversario, reglas de interacción (RoE), narrativa, escenarios, plugins vinculados, criterios de cierre y persistencia JSON local. |
| Reglas | Condiciones y acciones declarativas en YAML; respuesta a eventos o evaluación explícita del vencimiento. |
| Plugins | Contrato `deploy()`/`rotate()`/`retire()`, bus síncrono en el mismo proceso y un `MockHoneypotPlugin` de referencia. |
| Telemetría | Registro normalizado por evento, conservación del payload original y consultas de eventos, TTP e indicadores por operación. |

El [ejemplo completo](examples/quickstart.py) crea una operación y enlaza dos plugins simulados. Al desplegar el primero se emite un escaneo sintético; una regla despliega el segundo y activa la operación. Un acceso simulado la marca comprometida. Finalmente, el ejemplo establece una fecha vencida, llama a `check_closure()`, retira los plugins y cierra la operación. Las [tres reglas YAML](examples/rules_example.yaml) se pueden leer y modificar directamente.

No hay planificador en segundo plano: quien integra el motor debe llamar a `RuleEngine.check_closure()` para evaluar reglas de vencimiento. El bus y el motor se ejecutan sincrónicamente en el mismo proceso.

El diseño centrado en la operación se apoya en la investigación de Federico Pacheco y Diego Staino sobre el paso de CTI a ciberengaño. Este repositorio expone una base ejecutable de esa arquitectura: no implementa la metodología completa de siete pasos ni incluye un catálogo MITRE Engage. El recorrido sintético demuestra comportamiento del software, no efectividad defensiva en campo.

## Reglas de interacción y seguridad

`allowed_actions` y `forbidden_actions` restringen las acciones del **motor de reglas** mediante firmas generales (`deploy`) o específicas (`deploy:honeypot-mock-2`, `transition:closed`). Una prohibición tiene prioridad; una lista de permitidas vacía no restringe. El motor ignora eventos de otra operación o de plugins no vinculados, limita las cadenas recursivas y deja los rechazos por RoE o por límite de cascada en `RuleEngine.rejected_actions` durante ese proceso.

Estas guardas no autentican operadores ni protegen llamadas manuales a plugins. El entorno y las restricciones legales de texto libre son metadatos de la operación: un conector externo debe aplicar sus propios límites sobre la infraestructura. El [plugin simulado](src/apate/plugins/mock.py) muestra cómo implementar el [contrato](src/apate/plugins/base.py); no despliega recursos reales.

## Alcance y relación con Parallax

Esta edición es una **biblioteca alfa y una demostración local**, no un plano de control listo para producción. No incluye consola web, cuentas/OIDC, API administrativa, ledger gobernado, aprobaciones corporativas, conectores de despliegue ni stacks de terceros. La persistencia JSON no ofrece control de concurrencia, cifrado ni auditoría resistente a alteraciones. La telemetría normaliza observaciones; no demuestra causalidad de ataques ni efectividad defensiva.

**Apate Core** es la base pública y de código abierto. **Parallax** es un producto comercial separado, desarrollado en un repositorio privado. Aquí no se incluye su implementación empresarial.

## Licencia y colaboración

Apate Core se distribuye bajo [AGPL-3.0-or-later](LICENSE). Copyright © 2025 BASE4 Security. Autor del software: Federico Pacheco. Este repositorio no incluye código vendorizado de terceros. Para reportar un problema o proponer una mejora acotada, abrí un [issue](https://github.com/fedequark/Apate-Cyberdeception/issues) con versión de Python, pasos de reproducción y resultado esperado, sin credenciales reales ni telemetría sensible.
