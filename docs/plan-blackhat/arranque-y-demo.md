# Arranque local, configuración y demo de cinco minutos

Desde la raíz de tu checkout. Python probado: 3.12.11. Conservar entornos, bases y configuración existentes. [Resultados observados](estado-ejecucion.md), [guion técnico de demo](../../evals/DEMO.md) y [evaluación offline](../../evals/README.md).

Preparación nueva del piloto: [documentos y navegador](documentos-y-ensayos-piloto.md), [ejecutor y aprobación real pendiente](ejecucion-real-y-calibracion-piloto.md), [laboratorio Linux/PostgreSQL/HTTPS y recuperación](operacion-y-recuperacion-piloto.md). Los recuentos de la demo antigua que aparecen abajo son históricos; la máscara obligatoria añade sus llamadas a las fichas actuales.

## Instalación y comprobación

Solo si no existe `.venv`, crearla. La lista raíz es la única fuente; no instalar la interior por separado:

```powershell
rtk proxy uv venv --python 3.12.11 .venv
rtk proxy uv pip sync --python .venv/Scripts/python.exe requirements.txt
rtk proxy .venv/Scripts/python.exe regulai/manage.py check --settings=regulai.test_settings
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front api --settings=regulai.test_settings
rtk proxy .venv/Scripts/python.exe regulai/manage.py makemigrations --check --dry-run --settings=regulai.test_settings
rtk proxy uv tool run pip-audit -r requirements.txt
```

Los tests usan una base aislada y proveedores simulados. El resultado de la auditoría y las versiones se registran por fecha; [dependencias comprobadas](dependencias-verificadas.md). La sincronización reemplaza paquetes del entorno virtual elegido, no datos de la aplicación.

## Demo recomendada, sin salida del servidor a proveedores ni claves reales

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py run_demo --settings=regulai.demo_settings
```

Abrir `http://127.0.0.1:8001/login/`, usuario **`community-demo`**, contraseña pública sintética **`community-demo-only`**. Si ese puerto está ocupado, añadir `--port 8002`. Para preparar sin servidor, añadir `--seed-only`.

Usa exclusivamente `regulai/community-demo.sqlite3` y `regulai/community-demo-media`, con cookies propias. Migra y siembra una vez. Reiniciar conserva conversaciones y contraseña. Si alguien cambia el fixture de configuración, perfiles, credenciales, catálogo o reglas, falla sin sobrescribirlo: revisar la diferencia, no borrar la base para esconderla. Durante este comando están simuladas generación y HTTP de Jev; el proceso servidor bloquea las demás conexiones HTTP y socket. Los recursos vendor y los iconos usados son locales, con hashes comprobados; Iconify no hace fetch externo y las fuentes son del sistema. CSP solo Report-Only. El bloqueo de run_demo se aplica al servidor. El banner **DEMO OFFLINE — fallo simulado** distingue esos resultados de una llamada real. El arranque normal no instala estos parches.

### Guion de cinco minutos

| Tiempo | Acción exacta | Qué enseñar |
| --- | --- | --- |
| 0:00–1:00 | Chat, motor **Synthetic economy**, enviar `Devuelve el saludo Hola.` | Respuesta prefijada, ruta autorizada, comprobaciones y coste **simulado**. No anunciar ahorro real. |
| 1:00–2:00 | Conversación nueva; enviar `SYNTHETIC_SECRET_DEMO` | Bloqueo YARA y ficha con cero llamadas; no sale al clasificador ni al generador simulado. |
| 2:00–4:00 | Conversación nueva, **Synthetic economy**, adjuntar `evals/documents/demo-contract.txt`; preguntar `¿Cuál es el precio del contrato?` | El primer fixture responde 900 euros y el juez prefijado lo rechaza; segundo intento fuerte devuelve 10 euros. Abrir los intentos y la evidencia del contrato. No presentar al juez prefijado como prueba de exactitud real. |
| 4:00–5:00 | Abrir la ficha/evidencia y explicar cobertura, llamadas y coste desconocido; si queda tiempo, **Policy simulator**, comparar localmente un borrador | Una regla que encuentra `public` puede bloquear el informe público sintético. Probar una corrección que encuentre `synthetic secret`, sin activarla durante la presentación. |

Otros documentos piden aclaración en esta demo; otros mensajes generales usan el saludo sintético. Se comprobaron las tres escenas en navegador: saludo `Hola` con ruta automática y tres llamadas simuladas; secreto bloqueado con cero llamadas; contrato de 10 euros con cita en línea 2, dos generaciones/cinco llamadas simuladas y persistencia tras recargar. Cancelar una advertencia termina en `cancelled` sin respuesta; confirmar con el archivo original mantiene una sola burbuja de usuario y devuelve `10 euros [1]`. El simulador comparó y activó una política local en otra empresa sin credenciales ni destinos, con cero llamadas reales. Se probó Enter para enviar y abrir la ficha y Espacio para alternar la ruta automática. La apertura de citas y evidencia con Enter quedó comprobada el 3 de octubre en un navegador real contra Django offline; [siete capturas y límites](../../evals/reports/ui-community-fixes-20261003/README.md). El DOCX se generó con Python, no con Word/LibreOffice. Capturas en [estado observado](estado-ejecucion.md). Los dos ensayos humanos completos permanecen pendientes hasta realizarse y registrarse.

## Servidor de desarrollo normal

Solo para una base de desarrollo identificada, tras conservar copia de la base y de la configuración. El bootstrap crea `local_settings.py` únicamente si falta y genera claves sin imprimirlas. Si ya existe, se conserva; comprobar que su base es la de desarrollo antes de migrar.

```powershell
rtk proxy .venv/Scripts/python.exe scripts/bootstrap_local.py
rtk proxy .venv/Scripts/python.exe regulai/manage.py migrate
rtk proxy .venv/Scripts/python.exe regulai/manage.py runserver 127.0.0.1:8765 --noreload
```

La base local preparada es `regulai/community-local.sqlite3`. La cuenta sintética existente `community-local-demo` / `Local-demo-only-2026!` se usa solo en loopback. Actualmente `ai_config={}`: el envío devuelve 503 con cero llamadas. No importar claves reales ni activar llamadas durante el ensayo offline.

Con `--noreload`, reiniciar el proceso después de editar plantillas para ver los cambios: Django puede mantenerlas en caché. La preparación de recursos locales mediante `scripts/vendor_assets.py` fue comprobada; no hace llamadas a modelos.

Un administrador de empresa trabaja sobre su empresa. El catálogo global y Django admin requieren un operador activo con `is_staff`, `is_superuser` e ID explícito en `PLATFORM_ADMIN_USER_IDS` de la configuración local. Usar únicamente IDs de operadores elegidos; no conceder el ámbito global a todos los administradores de empresa. No abrir `media/` como ruta pública; las descargas y avatares pasan por vistas autenticadas.

## Configuración IA de ejemplo, sin secretos

### Una clave propia por servicio desde Settings

El administrador de cada cuenta de empresa puede abrir **Settings > Conexiones IA**
(`/settings/ai/`). Hay seis campos independientes: clave nativa de Anthropic para
Claude, Google para Gemini, Mistral, OpenAI y DeepSeek; el último recibe una clave de Vercel AI
Gateway exclusivamente para TypeSafe Jev. Los cinco generadores se conectan directamente
con su proveedor. No hay clave común ni copia de credenciales entre servicios. Los
campos vacíos conservan sus claves; se puede configurar solo un servicio.

Las claves quedan cifradas y aisladas por empresa. Guardar no consume créditos, prueba
el acceso ni concede permisos de salida. Para una empresa sin política ni enmascarado,
el segundo paso permite revisar y **Activar chat básico** después de guardar una clave
de generación. Crea enmascarado local y reglas de bloqueo de credenciales; autoriza solo
los generadores revisados para texto público/interno, con selección manual y hasta 1.000
tokens de respuesta. Los textos se consideran internos sin clasificación semántica;
no introducir información confidencial. No configura un presupuesto monetario ni inventa
precios: el coste desconocido sigue desconocido. Jev, documentos y políticas existentes
requieren la configuración avanzada. La revisión firmada caduca a los 30 minutos y una
rotación de clave o cambio de proveedor exige revisar de nuevo. La migración
0034 añade el catálogo directo sin transformar claves antiguas ni sustituir conexiones. Ver
[alcance y comprobaciones de esta sección](tareas/40-conexiones-ia-por-cuenta.md).

[ai-config-example.json](ai-config-example.json) valida con `AIConfig` y **mantiene cerrada la salida**: sin destinos, sin candidatos, presupuesto cero. Es una base segura para editar en el simulador, no una política que produzca respuestas.

Para una política autorizada, configurar destinos por sensibilidad: `obfuscation:<id>` es obligatorio para las máscaras activas y compatibles; añadir `engine:<CompanyEngine.id>` y `jev` según el recorrido. La credencial de Jev va en el campo cifrado `Company.jev_api_key`; las de generación en `CompanyEngine.api_key`. Ninguna pertenece al JSON. Los modelos activos necesitan contexto, salida máxima, supports_json/reasoning, moneda USD, fecha y tarifas vigentes **por millón de tokens**, calidad por tarea sustentada en evidencia y reglas YARA válidas. Un presupuesto acotado rechaza precios desconocidos.

Ejemplo de **un candidato**, con IDs de muestra que deben sustituirse por filas activas de la propia empresa:

```json
{"company_engine_id": 101, "model_id": 201, "level": "economy", "quality": {"general": 0.5}}
```

El ID 101 sería de `CompanyEngine`; 201 sería de `EngineModel` del mismo motor. El simulador revalida pertenencia y actividad. El valor de calidad anterior es ilustrativo, no calibrado. Para semántica requerida, también hacen falta permiso real hacia Jev, acceso de cuenta, tarifas y límite contractual por llamada. El acceso Gateway se comprobó el 2 de octubre bajo otra autorización del usuario: tres llamadas Jev correctas. El flujo documental se detuvo por clasificación ambigua; la calibración y la comprobación completa en vivo siguen pendientes. No comprar créditos automáticamente ni confundir esta comprobación con la demo offline.

### Activar el enmascarado de la empresa

La aplicación exige un servicio de enmascarado propio, activo, autorizado y con `detect=both` para datos personales y secretos. Entrada, instrucciones, historial elegible, fragmentos/localizadores y respuesta pasan por las máscaras activas antes de salir a otros destinos. Sin máscara válida se devuelve `masking_required` y no hay salida externa; desactivación, sustitución incompatible, timeout o lote inválido también detienen el recorrido. Chat y simulador semántico revalidan empresa, política, permisos e identidad de los destinos antes de llamar. Activar la política de IA o generar un borrador no crea ni activa esos servicios.

1. Instalar las dependencias fijadas y ensayar la migración0032 en una copia aislada, conservando base, medios y claves. El [detector integrado](enmascarado-local.md) funciona en CPU dentro de Django; no requiere URL, clave ni llamada a DeepSeek. No descarga modelos durante una petición.
2. Con un usuario autorizado para la sección de seguridad (staff o superuser), abrir `/obfuscation/` y crear/configurar una ObfuscationConfig de **su propia empresa**. Seleccionar backend **local**, nombre, detección **PII y secretos (`both`)**, lengua vacía/es/en y Active. La URL puede quedar vacía. La activación usa POST con CSRF; administrar la política de IA no concede por sí solo acceso a esta sección de seguridad.
3. Incluir `obfuscation:<id>` en los destinos permitidos para las sensibilidades admitidas, además del motor y Jev cuando corresponda. Una cadena exclusivamente local exige `masking.max_call_cost: "0"` explícito; representa coste API cero, no CPU o alojamiento gratis. El original permanece en el proceso local. Restricted sigue bloqueado antes del detector.
4. Comparar el borrador y revisar/activar la política mediante el POST auditado separado. Probar contenido sintético y revisar omisiones/falsos positivos del detector. La configuración no demuestra anonimización perfecta. Cambios de empresa, política, consentimiento o backend se revalidan antes de continuar.

El backend **HTTP** sigue disponible para un servicio autorizado compatible con PasteGuard. Requiere URL sin credenciales; llama a `POST <api_url>/api/mask`, con `text` como **string de un array JSON de strings**, `detect` con ambas categorías y lengua opcional. Debe devolver `masked` como string de un array JSON de strings de igual longitud y orden. El servicio recibe originales y necesita autorización de destino y cota contractual explícita; su fallo o contrato incompatible bloquea. Las cadenas mixtas reservan las cotas HTTP además de registrar el cómputo local a API cero. No hay fallback automático de local a HTTP.

Compatibilidad: la migración0032 añade el selector y conserva los registros existentes como HTTP, incluidas URL y actividad. Los históricos no se reescriben. Las políticas sin máscara compatible/autorizada o sin cota suficiente fallan cerradas; no se activa ni autoriza el backend local automáticamente. Para revertir0032, parar la aplicación y ejecutar la migración corregida antes de cambiar el código: desactiva las filas locales para que una URL antigua no vuelva a recibir originales. Los HTTP existentes permanecen intactos. Reactivar un destino remoto requiere revisión expresa; un downgrade ya realizado con la migración antigua necesita revisión manual antes de arrancar.

### Política inicial y cambio incompatible

`ai_config={}` devuelve HTTP 503 y cero llamadas. Multiempresa sigue disponible; `ALLOW_REGISTRATION=False` desactiva registro público. El administrador de cada empresa puede comparar y activar su política sin staff/superuser globales. El botón de borrador y este comando generan propuesta y avisos:

```powershell
python regulai/manage.py bootstrap_ai_policy --company ID --dry-run
```

Sustituir ID por la empresa autorizada. **El comando siempre deja la política activa intacta, también sin --dry-run.** Su suelo local es internal; solo propone destinos public/internal de motores y máscaras activos, no confidential/restricted/unknown ni Jev. No inventa calidad: completar las carencias señaladas, precios USD/millón y cota explícita de máscara (incluso cero de servicio propio). Unknown se trata como confidential por defecto; restricted permanece bloqueado incluso hacia motores privados.

Comparar primero en modo local, sin salida a proveedores. Revisar destinos por sensibilidad, catálogo, reglas, capacidad, calidad y costes antes de activar. El modo semántico requiere autorización vigente, cota contractual, consentimiento y presupuesto; tener una clave Jev no concede permiso implícito. Mantener secretos en campos cifrados/configuración restringida, nunca en JSON o comandos del historial.

La activación del simulador es un POST separado tras revisar la comparación. Revalida el borrador y comprueba versión/digests de política y reglas. Una edición concurrente o prueba expirada exige repetir la comparación.

## Evaluación repetible

Elegir un directorio **nuevo** para conservar informes anteriores:

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py evaluate_ai --settings=regulai.test_settings --output evals/reports/offline-repeticion-local
```

El comando acepta SQLite en memoria, ejecuta 50 casos en tres configuraciones y bloquea red externa. Rechaza una salida ya existente. Informe histórico del 2 de octubre: [offline-2026-10-02-04](../../evals/reports/offline-2026-10-02-04/report.md), con hashes SHA-256 de los bytes exactos de su revisión; no describe el código actual. La ejecución actual se enlaza desde [estado observado](estado-ejecucion.md). Si cualquier control falla el CLI guarda los cinco informes y termina con código distinto de cero. `--real` está desactivado en este banco; las pruebas reales acotadas fueron otro comando con registro persistente y no deben repetirse como parte del arranque.

## Recuperación

Para SECRET_KEY/FALLBACKS y ENCRYPTION_KEY/FALLBACKS, seguir el [procedimiento de rotación offline](rotacion-claves.md). No perder las claves que descifran datos y backups anteriores. La operación descrita no se ejecutó sobre ninguna base del usuario.

1. Demo offline: terminar con Ctrl+C. Sus parches desaparecen con el proceso; iniciar el servidor normal con sus settings habituales conserva sus datos. No borrar la base normal ni sustituir claves para retirar la demo.
2. Cambio de política: copiar `previous_config` del AuditLog `policy_activate` correspondiente, compararlo como nuevo borrador y activarlo con una revisión nueva. Si las reglas cambiaron, reconstruir el borrador con `rule_before.yara_rule` y sus campos anteriores; `rule_after` registra la versión nueva. La auditoría está limitada a la empresa y no incluye la muestra ni credenciales. Si era una regla nueva y `rule_before` es nulo, desactivarla como cambio explícito revisado.
3. Error de proveedor o validación: mantener el estado explícito y la salida cerrada; usar la demo offline rotulada. No saltarse comprobaciones ni repetir automáticamente un resultado incierto.
4. Cambio de código/esquema: conservar una copia consistente de SQLite y settings antes de migrar. Volver a una revisión solo con su esquema y copia compatibles; no ejecutar una migración destructiva sobre la única base. Las claves de cifrado deben conservarse para leer credenciales existentes.

No hay despliegue autorizado. El presupuesto real conjunto histórico, autorizado el 2 de octubre, fue 1 USD; esta guía no autoriza nuevas llamadas. Tras la repetición autorizada, el [registro actualizado](../../evals/reports/real-budget-2026-10-02-02.json) suma 0,000086946 USD conocidos (incluye la estimación DeepSeek de 0,00000870 USD) y mantiene reservas inciertas de 0,03 USD. No confundir esas reservas con cobro confirmado o con llamadas gratuitas. [Alcance y pendientes](estado-ejecucion.md).
