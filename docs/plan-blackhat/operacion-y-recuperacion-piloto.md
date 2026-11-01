# Operación y recuperación del piloto sintético

Especificaciones: [12](12-demo-y-salida.md), [rotación](rotacion-claves.md), [tarea 25](tareas/25-operacion-y-recuperacion.md). La validación descrita aquí es local y aislada. No se ha desplegado el producto, ejecutado CI remoto ni tocado la base del usuario.

## Entorno comprobado

Docker Desktop 4.88.1 con motor Linux 29.7.2 en esta estación Windows. El [laboratorio](../../scripts/pilot_lab.py) construye desde una copia de fuentes y [dependencias](../../ops/pilot/requirements.txt), con Python, PostgreSQL 17 y Nginx fijados por los [digests conservados](../../ops/pilot/images.json). Gunicorn usa la configuración del repositorio. El único puerto publicado se asigna dinámicamente a **127.0.0.1** para HTTPS; aplicación, proveedor sintético y PostgreSQL permanecen en una red interna sin salida a proveedores.

Se generan claves y certificado autofirmado exclusivos de cada ejecución. El certificado caduca en dos días y se verifica en las peticiones del ensayo. No se copia `local_settings.py`, `.env*`, bases, medios ni secretos existentes. Las claves y backups permanecen bajo `.claude/regulai-lab-<id>/private/`, excluido de Git. No se deben publicar esos directorios, aunque sus datos sean sintéticos.

La extensión añade únicamente `psycopg[binary]==3.3.6`, compatible con Python 3.12 según la [documentación de Psycopg](https://www.psycopg.org/psycopg3/docs/basic/install.html). No cambia las dependencias de la aplicación SQLite. Se comprueban `DEBUG=False`, hosts, cookies seguras, redirección HTTPS y cabeceras conforme a la [lista de despliegue de Django](https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/). Pasar `check --deploy` no acredita por sí solo seguridad de una infraestructura pública.

## Reproducción y parada

Desde la raíz, con Docker Linux disponible y el entorno virtual instalado:

```powershell
rtk proxy .venv/Scripts/python.exe scripts/pilot_lab.py --output evals/reports/pilot-operations-NUEVA-EJECUCION
```

El destino debe ser nuevo. Se conservan `source-manifest.json`, comandos, códigos de salida, duración y hash de cada log, imágenes, resultados HTTP y recibo tras interrupción. La primera construcción y las imágenes requieren acceso al registro de contenedores y a paquetes; las peticiones del producto solo llegan al contenedor sintético. No hay claves ni llamadas a proveedores reales.

El proceso comprueba la instalación, migra una base nueva, crea Alpha/Beta con dos usuarios y dos administradores en total, recoge estáticos y ejecuta `check --deploy --fail-level WARNING`. Los administradores no son operadores globales. Prueba HTTPS, descargas privadas, separación de empresas, detector local real sin API y SDK de generación con transporte HTTP sintético, bloqueo local, concurrencia e interrupción. Después ejecuta las pruebas PostgreSQL y la recuperación descrita abajo. Finalmente retira sus contenedores, volúmenes, redes e imagen temporal. Conserva informes y la carpeta privada de esa ejecución; no elimina archivos del usuario.

Para una sesión humana aprobada, se puede añadir `--serve-seconds 3600` (máximo 7200). Tras superar las verificaciones arranca de nuevo la aplicación y muestra el endpoint local y las credenciales **sintéticas y públicas**. `Ctrl+C` termina la sesión y ejecuta la limpieza. `endpoint.json` identifica URL y certificado; no se instala confianza global ni se expone la máquina. Una sesión abierta no cuenta como un ensayo humano realizado: las observaciones se recogen aparte.

## Evidencia observada

La [ejecución final10](../../evals/reports/pilot-operations-20261003-10/result.json), con detector CPU real y los correctores JSON/rollback, terminó exit0: **117 pruebas PostgreSQL en17,185s**, una omisión exclusiva de SQLite, recuperación completa y recursos propios retirados. La09 conserva114 pruebas anteriores a esos dos correctores. El [resumen nuevo](../../evals/reports/pilot-operations-20261003-summary-local/README.md) verifica diez ejecuciones, hashes de todos los logs y cero coincidencias de claves/marcadores sintéticos. Estos resultados sustituyen como candidato actual los snapshots HTTP descritos a continuación.

Las ejecuciones [06](../../evals/reports/pilot-operations-20261003-06/result.json), [07](../../evals/reports/pilot-operations-20261003-07/result.json) y [08](../../evals/reports/pilot-operations-20261003-08/result.json) terminaron con código 0. La última ejecución completó 84 pruebas PostgreSQL en 12,128 s; una prueba de trigger exclusiva de SQLite se omitió. El conflicto de recifrado se comprobó además con un escritor PostgreSQL real. La restauración y reversión coincidieron con el inventario de 27 tablas y dos archivos, con credenciales legibles. El endpoint supervisado arrancó durante un segundo en 07, sin participantes. Se conservaron los cinco intentos anteriores con su causa: inspección de imagen base, publicación sobre red interna, permisos de estáticos, login repetido por el harness y nombre de cookie asumido por una prueba. Sus resultados parciales no se presentan como puertas completas.

Resultados comprobados: un único envío ante solapamiento; desconexión del cliente sin generación duplicada; detención real de Gunicorn durante una llamada seguida de `outcome_unknown`, `success=false`, generación `started`, coste `null` y total ausente. La consulta posterior no reenvía. Se envejeció exclusivamente el registro sintético para atravesar el plazo de recuperación, sin esperar ni modificar el plazo del producto.

Los logs estructurados de aplicación omiten contenido y credenciales; la [verificación final conservada](../../evals/reports/pilot-operations-20261003-summary-final/verification.json), ejecutada con una copia idéntica del [verificador](../../evals/reports/pilot-operations-20261003-summary-final/verify_evidence.py), compara en memoria las claves sintéticas y el marcador sensible contra todos los logs, y verifica sus hashes. Resultado: ocho ejecuciones, hashes coincidentes y cero coincidencias de esos valores. La revisión adicional de 440 archivos de texto tampoco encontró las 24 claves sintéticas conocidas ni bloques PEM privados. Tras 08, las consultas Docker por etiqueta e identidad no encontraron recursos temporales; los backups privados permanecen retenidos. El transporte sintético solo registra propósito, hash de cuerpo y presencia del marcador. Este detector sustituye un marcador exacto; no demuestra detección general de secretos. [Resumen y comandos de cierre](../../evals/reports/pilot-operations-20261003-summary-final/README.md).

## Backup, restauración y recifrado

1. Detener escrituras de la aplicación del laboratorio. Obtener inventario y hash de filas de todas las tablas, archivos y comprobación de descifrado, sin volcar valores.
2. Guardar `pg_dump -Fc`, medios y claves de cifrado/firmado como un conjunto privado. La herramienta incluye los tres; conservar solo la base no basta.
3. Crear una segunda base `regulai_restored` dentro del mismo PostgreSQL aislado. Restaurar dump y copiar medios a `restored-media`; comparar recuentos y hashes con el inventario previo, y leer las credenciales sintéticas con las claves conservadas.
4. Provocar un escritor concurrente real entre lectura y actualización del recifrado. Debe abortarse la rotación completa, conservarse la escritura concurrente y mantenerse intactas las demás filas.
5. Añadir una clave nueva con la anterior como fallback, ejecutar dry-run y recifrado. Retirar el fallback y comprobar lectura con la nueva clave sola.
6. Para el ensayo de reversión, descartar **solo la copia restaurada**, restaurar de nuevo el dump y su juego anterior de claves. Comparar otra vez todos los hashes. La base origen del laboratorio y cualquier base del usuario quedan fuera de esa operación.

La suite también migra y revierte esquemas históricos 0028→0029→0030→0031 conservando importes, catálogo, decisiones, relaciones y auditoría. El cierre inicial D2 no añadía esquema; el backend local incorpora0032. Conserva los HTTP anteriores y, al revertir, desactiva los locales antes de retirar el selector para impedir que una URL antigua vuelva a recibir originales. Parar la aplicación y ejecutar la migración corregida antes de cambiar el código. Restaurar un backend HTTP exige revisión/autorización expresa. Un downgrade ya realizado con la versión antigua requiere revisión manual antes del arranque.

## Límites y siguiente entorno

El candidato inicial es una sesión local sintética supervisada. La [prueba documental de navegador](documentos-y-ensayos-piloto.md) usa además un runner Windows/SQLite con transporte simulado capaz de construir citas; ese entorno se identifica por separado del laboratorio Linux/PostgreSQL. La respuesta fija del transporte del laboratorio no sirve para medir calidad documental o semántica.

Una instalación pública exige propuesta propia: host, dominio/certificado público, responsable de secretos y backups, permisos de contenedor/host, retención, supervisión y salida de red autorizada. No se han validado alta disponibilidad, caída de la máquina completa, restauración en otro servidor ni CI remoto. El certificado local y el contenedor de laboratorio no constituyen una configuración final de producción. Ninguno de esos pendientes se cierra mediante este documento.
