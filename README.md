# Apate Core

Apate Core es una biblioteca abierta y ejecutable para modelar operaciones de ciberengaño. Une un objeto de operación, reglas deterministas, un contrato de plugins y telemetría básica. Esta primera versión trae un plugin simulado para probar el ciclo completo en una máquina local; no despliega señuelos reales ni se conecta a infraestructura de producción.

## Alcance de esta versión

- **Operaciones:** perfil de adversario, reglas de interacción (RoE), narrativa, escenarios, vínculos a plugins, criterios de cierre y persistencia JSON local.
- **Reglas:** condiciones y acciones declarativas en YAML. El motor aplica las RoE, limita cadenas recursivas y sólo actúa sobre plugins vinculados a la operación.
- **Plugins:** contrato `deploy`/`rotate`/`retire`, bus síncrono de eventos y `MockHoneypotPlugin` para ejecución simulada.
- **Telemetría:** normalización de eventos, TTP e indicadores observados, con persistencia JSON local.

No se incluyen la consola web, IAM/OIDC, API de administración, conectores AD/SMB/Vault, despliegues corporativos, ledger gobernado, DOLOS-T, BUDA ni el stack Playground. Los nombres de herramientas o superficies en los modelos son referencias de diseño: **no implican conectores ejecutables** en esta distribución.

## Relación con Parallax

Apate Core es el proyecto de código abierto. Parallax es el futuro producto comercial, mantenido en un repositorio privado distinto. Esta publicación no incorpora código privado de Parallax ni ofrece sus capacidades empresariales. La separación de repositorios es técnica y editorial; los términos comerciales se documentarán por separado cuando corresponda.

## Uso local

Requiere Python 3.10 o superior. En un entorno virtual:

```bash
python -m pip install -e ".[dev]"
python examples/quickstart.py
python -m pytest
```

El ejemplo crea una operación, enlaza dos plugins simulados, activa reglas desde `examples/rules_example.yaml`, genera eventos sintéticos y guarda la operación y la telemetría bajo `.apate_data/`. No usa red ni servicios externos.

## Garantías y límites

El motor no toma decisiones con un LLM. La ejecución es síncrona y local. Las RoE gobiernan las acciones **del motor de reglas**; quien integre un plugin debe aplicar sus propios controles a las acciones manuales y a la infraestructura externa. El bus y los archivos JSON no proporcionan control de concurrencia, autenticación, almacenamiento cifrado ni una auditoría resistente a alteraciones. Esta versión es una base de desarrollo y demostración local, no una plataforma lista para un despliegue empresarial.

## Licencia y atribución

Apate Core se distribuye bajo AGPL-3.0-or-later. Consulte [LICENSE](LICENSE). Copyright © 2025 BASE4 Security. Autoría: Federico Pacheco. Este repositorio no incorpora código vendorizado de terceros.
