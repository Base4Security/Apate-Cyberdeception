# Gates de versión y validación

*Estado: 6 de octubre de 2026. Esta edición comunitaria es una candidata local. Todavía no hay una versión estable ni una validación de campo.*

## Candidata técnica

Antes de etiquetar una versión, el mismo commit debe superar estos controles:

1. Suite completa en Windows y Linux con Python 3.10 y 3.12; publicar el resultado exacto y los tests omitidos.
2. Construir la wheel e instalarla en un entorno limpio. Comprobar que registra los siete plugins y que responden la consola, la API y `/about`.
3. Ejecutar el smoke local de operación, telemetría, auditoría y backup/restauración con datos sintéticos.
4. Verificar `NOTICE`, licencias de los componentes vendorizados, SBOM, dependencias fijadas y huellas SHA-256 de los artefactos.
5. Revisar un ensayo de actualización y restauración entre versiones. Conservar el resultado asociado al commit y a las ruedas exactas.

La suite local y el smoke no sustituyen la CI del commit que se publique. No se debe declarar una release candidate verificada hasta que esa CI y la revisión del artefacto descargado terminen en verde.

## Gates de laboratorio y piloto

| Integración o evaluación | Evidencia pendiente |
| --- | --- |
| AD y WEF | Alta, interacción, recepción de eventos y baja de honeyusers en un laboratorio aislado. |
| SMB y filesystem | Permisos mínimos, despliegue, detección, rotación y retirada de honeyfiles. |
| Vault KV v2 | Política mínima, lectura/escritura, error de permisos y recuperación. |
| Docker y capacidades externas | Ciclo real de OpenCanary, DOLOS-T, BUDA y Playground, con limpieza tras fallo. |
| IdP | Inicio de sesión OIDC, asignación de roles, revocación y aislamiento entre equipos. |
| SIEM/SOAR | Entrega, reintento, duplicados y trazabilidad de un receptor real. |
| Operadores | Evaluación de comprensión, tiempo y errores con usuarios ajenos al equipo de desarrollo. |
| Operación sostenida | Instalación con proxy/TLS, respaldo, recuperación, observabilidad y límites de capacidad. |

Todos estos gates externos permanecen **NOT_RUN** en esta candidata local. Cada resultado futuro debe registrar entorno, versión, procedimiento, evidencia y fallos observados antes de cambiar su estado.

## Alcance de las afirmaciones

Las pruebas locales respaldan contratos de software y recorridos sintéticos. No demuestran eficacia defensiva en campo, usabilidad con operadores externos ni alta disponibilidad productiva. Los informes y capturas de ejemplo deben identificarse como sintéticos.
