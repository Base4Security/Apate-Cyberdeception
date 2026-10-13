# Respaldo y restauración de datos

APATE guarda operaciones, identidad, planes, credenciales cifradas, auditoría y
SQLite bajo `APATE_DATA_DIR`. Para una copia **consistente como conjunto**, detené
el único proceso APATE antes de ejecutar los comandos. La API de backup de SQLite
protege cada base, pero no existe una transacción común con todos los JSON.

```powershell
python -m apate.backup create C:\apate\data D:\backups\apate-2026-09-15
python -m apate.backup verify D:\backups\apate-2026-09-15
python -m apate.backup restore D:\backups\apate-2026-09-15 C:\apate\data-restaurada
```

`create` exige un destino nuevo fuera del directorio de datos. `verify` revisa
SHA-256, tamaños y `PRAGMA integrity_check` de cada SQLite. `restore` solo acepta
un destino nuevo o vacío; nunca reemplaza datos en uso. Después de restaurar,
configurá `APATE_DATA_DIR` hacia el directorio nuevo, arrancá APATE y comprobá
una operación, una consulta de telemetría y la verificación de auditoría.

La clave Fernet local viaja en la copia cuando vive en el directorio de datos.
Si la instalación usa `APATE_SECRET_ENCRYPTION_KEY`, el manifiesto marca que hace
falta recuperar **esa misma clave** desde su custodio externo antes de arrancar:
el valor no se exporta ni se imprime. Si BUDA usa una base SQLite configurada
fuera de `APATE_DATA_DIR`, respaldala por separado; el comando rechaza ese caso
cuando detecta su URI. Guardá la copia con controles de acceso equivalentes a
los del directorio de datos y ensayá la restauración periódicamente.
