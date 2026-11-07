# Rotación de firmas y credenciales cifradas

Procedimiento contrastado con [checks.py](../../regulai/front/checks.py), [encryption.py](../../regulai/front/encryption.py), [reencrypt_secrets](../../regulai/front/management/commands/reencrypt_secrets.py), [plantilla de entorno](../../regulai/regulai/local_settings_template.py) y [bootstrap](../../scripts/bootstrap_local.py). Fue probado con claves sintéticas y bases de test; no se ejecutó sobre la base del usuario.

`SECRET_KEY` firma sesiones, consentimiento y activación; `SECRET_KEY_FALLBACKS` permite comprobar firmas antiguas durante una transición. `ENCRYPTION_KEY` cifra nuevos valores; MultiFernet lee con primaria y `ENCRYPTION_KEY_FALLBACKS`. Cambiar únicamente la primaria no recifra lo almacenado. Sin la clave que descifra un ciphertext no hay recuperación criptográfica: conservar claves y copia compatible antes del cambio.

Las claves fijas de la plantilla histórica pública `6a0f667` están comprometidas por ser públicas. `front.E001` rechaza cualquiera de ellas tanto en primarias como en fallbacks, sin mostrar valores. **La clave pública de firma nunca debe mantenerse como fallback de un servidor activo:** invalidar sesiones y tokens antiguos, incluyendo confirmaciones y activaciones, y volver a autenticarse/comparar. Para una clave de firma anterior que no sea pública ni comprometida, puede mantenerse temporalmente un fallback hasta expirar sus firmas; después retirarlo.

1. Identificar base y configuración objetivo; obtener copia consistente protegida y comprobar restauración en una copia aislada. Abrir ventana de mantenimiento, detener servidores, workers y toda escritura concurrente de credenciales. Guardar de forma segura las claves necesarias para los datos y backups que todavía dependan de ellas. No ponerlas en comandos, historial, repositorio, capturas ni logs.
2. Generar una SECRET_KEY nueva aleatoria y una ENCRYPTION_KEY Fernet nueva mediante un procedimiento privado que las escriba directamente en almacenamiento restringido. Configurar primarias nuevas. La plantilla lee las primarias del entorno y las listas de fallbacks como arrays JSON; el bootstrap usa listas vacías. El bootstrap solo crea settings si falta: no sustituye un archivo existente.
3. Preparar **configuración offline de mantenimiento** con la primaria Fernet nueva y las antiguas necesarias en `ENCRYPTION_KEY_FALLBACKS`. Si una antigua es la pública histórica, conservarla únicamente en este entorno offline para recuperar y abandonar esos ciphertext. No arrancar el servidor con ella. El comando omite los system checks deliberadamente para esa recuperación, pero rechaza expresamente una primaria de destino pública antes de escribir.
4. Sobre la copia restaurada, con el entorno de mantenimiento apuntando explícitamente a esa copia, ejecutar el dry-run. Revisa solo recuentos. No usar test_settings como sustituto de la copia que se pretende recuperar.

```powershell
python regulai/manage.py reencrypt_secrets --dry-run --batch-size 500
```

5. Tras validar la copia y autorizar la operación sobre la base objetivo, mantener todas las escrituras detenidas y ejecutar el recifrado con la misma configuración, omitiendo `--dry-run`. El comando lee columnas cifradas brutas, abarca todos los EncryptedCharField/EncryptedTextField registrados (actualmente Company.jev_api_key y CompanyEngine.api_key), procesa lotes de 1 a 10.000 y usa **una transacción global**. MultiFernet.rotate conserva el timestamp. Ciphertext inválido o fila cambiada que no cumpla el compare-and-swap aborta todo; no se sustituye una credencial por vacío.

```powershell
python regulai/manage.py reencrypt_secrets --batch-size 500
```

6. Antes de reabrir acceso, probar de nuevo lectura/dry-run en una copia con **solo la primaria nueva**, sin imprimir credenciales. Verificar cantidades esperadas y acceso local autenticado sin activar llamadas reales. Retirar fallbacks públicos del entorno normal, ejecutar `python regulai/manage.py check`, reiniciar y recuperar el servicio bajo control. Una transacción global puede exigir una ventana larga en catálogos grandes.
7. Para rollback, restaurar conjuntamente copia consistente y configuración/claves que la descifran en mantenimiento. No volver al antiguo servidor con clave pública: recuperar offline y recifrar de nuevo. Conservar las claves antiguas de backups todavía necesarios en custodia offline; migrar esos backups o definir su recuperación antes de destruirlas. Retirar también los fallbacks de firma no comprometidos al acabar su ventana de validez.

El bootstrap intenta crear el archivo con modo 0600 en POSIX. En Windows aplica `icacls`, retira herencia y concede acceso al usuario actual antes de escribir; si falla avisa explícitamente. Es protección best-effort: verificar permisos efectivos en el host objetivo. Los tests comprobaron permisos en temporales locales, atomicidad, dry-run, lotes, ciphertext inválido y rollback mediante un trigger SQLite que simula una actualización omitida. No acreditan procesos concurrentes reales ni PostgreSQL.
