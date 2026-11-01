# Instalación local con agente real

Este arranque usa Django ASGI, PostgreSQL y un worker que ejecuta código en
microVM E2B privadas. No arranca proveedores simulados ni carga conversaciones
de demostración. En una importación nueva se establece **admin / admin**; cambia
esa contraseña antes de usar la cuenta. El acceso se publica únicamente en
`127.0.0.1`.

**El instalador requiere un perfil privado de una instalación ya configurada.**
No hay un asistente público para crear desde cero la primera empresa, sus
usuarios, proveedores y permisos del agente. El repositorio no incluye ese
perfil ni claves de API. Sin él, la instalación se detiene antes de crear la VM.
Este procedimiento sirve para importar una configuración autorizada a un entorno
local de desarrollo; no es una receta de despliegue público.

## Requisitos

- Windows x86-64 con Docker Desktop/WSL2, o Linux x86-64 con Docker Engine.
- Virtualización de CPU habilitada y `/dev/kvm` disponible para Docker, con
  virtualización anidada. El instalador prueba que puede crear una VM KVM real.
- Python 3.11 o posterior para el lanzador anfitrión; los contenedores de
  aplicación y ejecutor usan Python 3.12. Docker en modo contenedores Linux.
- Al menos 10 GiB asignados a Docker, 16 GiB de RAM física recomendados y
  50 GB libres para imágenes, caché y disco persistente.
- Internet para descargar Ubuntu y construir las imágenes. La primera
  instalación tarda bastante más que los arranques posteriores.

Mac/ARM no está soportado por este ejecutor local. No se sustituye E2B por
ejecución en el equipo anfitrión cuando falta KVM.

## Primera instalación

1. Descarga o clona este repositorio.
2. Obtén de un operador autorizado el archivo privado **regulai-private.json**.
   Debe proceder de una instancia compatible ya configurada, con un usuario
   `admin` activo y superusuario, una conexión real y un perfil profesional
   habilitado con su concesión de acceso. El exportador para operadores está en
   `ops/agent_chat/export_install_profile.py`; se ejecuta dentro del entorno
   Django de origen con sus ajustes cargados. No es una plantilla de ejemplo.
   Contiene usuarios, conexiones API y políticas: consérvalo preferentemente
   fuera del repositorio. No lo compartas junto al código ni lo subas a
   incidencias o capturas. También se admite junto a `setup.py`, donde está
   excluido de Git.
3. Con Docker arrancado, ejecuta desde la carpeta del proyecto:

   Windows:
   ```powershell
   .\setup.cmd install --private-profile "C:\private\regulai-private.json"
   ```

   Linux:
   ```sh
   sh setup.sh install --private-profile /private/regulai-private.json
   ```

   Equivalente mediante Python:
   ```sh
   python setup.py install --private-profile "/ruta privada/regulai-private.json"
   ```

4. Cuando aparezca `READY`, abre <http://127.0.0.1:8800/login/> y entra con
   **admin / admin** en una importación nueva. Cambia la contraseña. La
   disponibilidad del agente depende del perfil y los permisos importados.

El instalador crea claves internas nuevas para cada equipo y vuelve a cifrar
las credenciales importadas. No importa chats, archivos generados, sesiones ni
facturación histórica. Reiniciar o repetir la instalación no restablece una
contraseña que ya hayas cambiado.

## Uso diario

```sh
python setup.py start
python setup.py status
python setup.py stop
```

Mantén abierta la ventana de `start`: proporciona el túnel local. `Ctrl+C`
cierra el acceso local; `stop` detiene los servicios. Los datos permanecen en
el volumen Docker `regulai-v2-state`. No borres ese volumen para actualizar.
El instalador no reemplaza una instalación ajena ni elimina datos existentes.
No es un procedimiento de actualización automática entre versiones.

Si el puerto 8800 está ocupado, identifica el servicio o usa `--port 8801`.
`python setup.py doctor` comprueba Docker, arquitectura y memoria; el arranque
comprueba además KVM anidado, PostgreSQL, web, E2B y conversión DOCX/PDF en una
microVM con salida directa a Internet bloqueada. Si una comprobación falla,
no muestra `READY`. Consulta `docker logs regulai-v2-vm` para fallos de la VM.

## APIs y alcance

Los proveedores y modelos disponibles son los del perfil que importe cada
operador. Las peticiones al modelo consumen el saldo de esas APIs. La instalación y sus
pruebas de disponibilidad no hacen llamadas de generación de pago.
La búsqueda con Tavily requiere su configuración y autorización propias; no se
incluye una clave en el repositorio. La lectura web y la instalación de paquetes
pasan por las políticas del servidor. El lanzador configura esas capacidades,
pero los permisos del perfil siguen siendo obligatorios. El navegador JavaScript
del agente permanece desactivado en la configuración de este instalador.

`admin/admin` es una contraseña inicial conocida para desarrollo local. Este instalador
no configura un servidor público ni HTTPS. No expongas su túnel en la LAN.

## Comprobaciones del código

```sh
python -m unittest ops.setup.test_installer ops.setup.test_chat_bundle
```

CI ejecuta cada módulo en un proceso nuevo: SQLite para las evaluaciones
aisladas heredadas y PostgreSQL para el agente. La prueba marcada
`namespace_integration` requiere el laboratorio Linux preparado y no forma
parte de ese CI. La disponibilidad real de E2B y LibreOffice se comprueba
además durante `setup.py start`.

Estas pruebas del lanzador no construyen una instalación nueva ni prueban la
calidad del proveedor real. La validación de una instalación completa requiere
el hardware indicado, un perfil privado autorizado y las comprobaciones de
`install`/`start` en ese equipo.

Las dependencias de aplicación y ejecutor se construyen en contenedores; no
hace falta instalar RTK, uv, Node, LibreOffice ni PostgreSQL en el anfitrión.
Las versiones Python, PostgreSQL, SDK y plantillas se fijan en los Dockerfiles
y locks. Los paquetes del sistema de la VM se descargan de Ubuntu; la
reproducibilidad aquí es funcional, no una imagen idéntica byte a byte.
