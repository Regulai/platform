# 58 — Instalación local reproducible del agente real

Estado: instalación validada; entrega en `JaviCKP/RegulaiV.2`.

## Entrega

El usuario solicita clonar/descargar `JaviCKP/RegulaiV.2`, arrancar con pocos
pasos y disponer de la cuenta `admin/admin` y la conexión real existente.
Autoriza publicar el código en ese repositorio privado. Las credenciales
reales se entregan fuera de Git mediante un perfil privado importable.

`setup.py`, `setup.cmd` y `setup.sh` aprovisionan una VM nueva con E2B propio,
PostgreSQL, web ASGI y worker. Requieren Docker Linux x86-64 con KVM anidado,
Python 3.11+, al menos 10 GiB para Docker y espacio para las imágenes.
No se promete compatibilidad con Mac/ARM ni arranque sin virtualización.

## Comprobaciones observadas

- VM nueva y volumen Docker vacío; Ubuntu verificado por SHA-256 y KVM probado.
- Construcción desde cero de web, worker y sandbox: no imagen local de tarea 48
  como dependencia del worker, ni arranque predeterminado de laboratorio.
- PostgreSQL vacío migrado; importación de cuenta, conexión, política y permisos.
  Sin chats, sesiones, documentos ni facturación histórica.
- Login HTTP con `admin/admin`; chat, conexiones IA y admin devuelven 200;
  el selector abre el agente por defecto.
- Parada y arranque completos; contraseña y conexión conservadas, cero chats.
- DOCX convertido a PDF en E2B real a través de `WorkspaceSandbox`, UID 1000,
  sin `/run`, con salida directa bloqueada en el espacio de red del comando.
  La API de control de E2B queda fuera del espacio de ejecución del código.
- Autenticación real de DeepSeek mediante lectura de catálogo: HTTP 200 y
  modelo `deepseek-flash` disponible. Cero llamadas nuevas de generación.
- Exportación privada de la conexión actual; búsqueda de sus claves exactas
  y de secretos de `local_settings.py` en la distribución: sin coincidencias.
- 677 pruebas de aplicación aprobadas por módulos con su backend correspondiente,
  3 pruebas del instalador aprobadas y ausencia de cambios de migraciones.
  Las pruebas automatizadas de aplicación usan dobles controlados; la prueba
  de disponibilidad del instalador utiliza E2B y LibreOffice reales.
- La comprobación HTTP de arranque no consume intentos del límite de login.
- CI detectó avisos de seguridad en MCP 1.26.0. Se actualiza únicamente MCP
  a 1.28.1 y se regeneran los locks del servidor Python 3.12/Linux. Las nueve
  pruebas MCP pasan y `pip-audit` no encuentra vulnerabilidades conocidas en
  las dependencias auditables; el modelo spaCy externo a PyPI queda excluido.

## Correcciones de reproducibilidad

El arranque normal no vuelve a ejecutar los trabajos de descarga de artefactos
de E2B: una segunda ejecución del trabajo original falló al consultar un hash
remoto. Restaura la configuración del host y arranca los servicios persistentes.
La primera instalación sigue verificando los artefactos mediante E2B.

Las pruebas de aplicación heredadas usan SQLite deliberadamente; las de agente
requieren PostgreSQL. CI separa módulos y procesos, mantiene las comprobaciones
de permisos/red/migración y prepara un entorno SDK independiente. La integración
con el laboratorio de namespaces sigue siendo explícita; no se hace pasar por
una ejecución real de E2B ni por una llamada a un modelo real.

La revisión encontró además que el enmascarado podía alterar referencias opacas
de imagen con muchos dígitos. Se conserva su estructura y se comprueban los
permisos de la imagen antes de enviarla; el caso de referencia inexistente tiene
una prueba determinista.

## Límites conservados

Solo está configurada la conexión DeepSeek existente. No hay clave Tavily.
El navegador JavaScript del agente sigue desactivado; sí hay lectura web
gobernada. El modelo configurado no tiene visión. `admin/admin` se expone solo
por túnel loopback, nunca como despliegue público. Los paquetes del host se
descargan de los repositorios del sistema: reproducibilidad funcional, no binaria.

## Enlace público temporal

Para una demo, el contenedor web puede aceptar un único origen https exacto con
`REGULAI_PUBLIC_ORIGIN=https://nombre.trycloudflare.com` (`ops/setup/server.py`);
sin la variable sigue siendo solo loopback y no se admiten comodines. Antes de
compartir el enlace se cambia la contraseña de `admin`. Cerrar `cloudflared`
corta el acceso; para volver a loopback se recrea el contenedor sin la variable.
