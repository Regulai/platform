# Chat regulAI: inventario de estados para la isla React

Base: snapshot `2bfb930` del árbol de trabajo compartido (`a16d039` + P0/P1 sin
confirmar, equivalente a `cc46b71` de la tarea 77). Especificación:
[prompt de renovación](../../output/chat-ui-research-20261017/prompt.md) e
[investigación](investigacion-chat-ui-20261017.md). Tareas
[79](tareas/79-chat-react-base.md)–[82](tareas/82-chat-react-retirada-legado.md).

Cada fila indica qué sabe la persona, qué puede hacer y qué hecho del servidor lo
justifica. Ningún estado se deduce del tiempo transcurrido ni del HTML generado.

## Página y navegación

| Estado | Fuente autoritativa | Representación nueva |
| --- | --- | --- |
| Chat vacío (chat/agente/profesional) | `chat_view`, `agent_available`, `agent_professional` | Saludo de una línea, compositor como foco; sugerencias sólo en Agente (máx. 2) |
| IA sin configurar | `ai_setup_missing`, `can_manage_company_policy` | Aviso accionable sobre el compositor; enlace a Conexiones IA si hay permiso |
| Demo offline | `community_demo_mode` | Franja fija; es una declaración de seguridad, no decoración |
| Conversaciones agrupadas, búsqueda, sin resultados | `conversation_groups` (títulos enmascarados) | Lista lateral; panel ocultable (localStorage `regulai.chat.threads`); cajón modal < 1024 px |
| Navegación de la aplicación y cuenta | `nav_items.html` + context processor | Menú de cuenta con secciones agrupadas; paridad probada con la plantilla |
| Alertas (staff) | `unresolved_alerts_count`, `recent_unresolved_alerts` | Botón con recuento y menú de últimas alertas |
| Proveedor/modelo, automático, límites del proveedor | sesión + `selectEngine/selectModel`, `ai_config` | Menú en la barra del compositor; «Límites del proveedor» dentro del menú |

## Compositor

| Estado | Regla conservada |
| --- | --- |
| Vacío / con texto | Enviar deshabilitado sin texto ni archivo; autoaltura ≤ 40 % de la ventana |
| IME | Enter con `isComposing`/229 no envía; Shift+Enter nueva línea |
| Archivo seleccionado / rechazado | Uno por envío; tipos según modo (`accept`), tamaño según servidor; error corto en el propio chip |
| Arrastrando | Sólo sobre la superficie del compositor y sólo con `Files`; respeta disabled |
| Ocupado | Una petición a la vez; Enviar → Detener cuando el servidor admite detener; pista «Pendiente de tu aprobación/revisión» |
| Modo Chat/Agente | Sólo en conversación nueva con agente disponible; cambia placeholder, tipos, skills, Drive y perfil |
| Perfil de respuesta | Profesional con > 1 perfil |
| Contexto | Archivo de Drive, revisión en edición o revisión a la que se aplicarán cambios; se puede quitar |
| Drive | Búsqueda CSV/XLSX en carpeta autorizada, sólo Agente |
| Skills | `/` literal (sin IME, caret en 1) o botón; catálogo diferido; ≤ 3; Auto persistente; borrador y selección pendiente al volver de la biblioteca; por debajo de 640 px, hoja inferior con el mismo contenido; sólo la lista se desplaza |

## Turno de chat (petición web)

| Estado | Evento/campo | Representación |
| --- | --- | --- |
| Adjunto enviando → recibido | upload en curso → cabeceras SSE/`accepted` | Chip con actividad indeterminada → recibido; sin porcentajes |
| Etapas | `stage` protecting/classifying/generating(+modelo, intento)/verifying/waiting | Una línea Trace con icono y texto presente |
| Entrega completa | `delivery` mode `complete` + reason | Nota breve en la línea |
| Texto progresivo | `delta` por `seq`, intento | ChatMarkdown, bloques estables, sin animar historial |
| Texto retirado | `retract` | Desaparece del DOM y de copiar; línea «Reintentando»/«Comprobando» |
| Completada | `final` completed | Respuesta, «No verificado» si procede, archivo, citas, copiar, detalles |
| Bloqueada / confirmación / cancelada / error | `final` status + códigos | Aviso corto con causa, efecto y acción (confirmar, cancelar, comprobar, reenviar); un bloqueo sin regla coincidente muestra el motivo de la política (`error`, también tras recargar vía bootstrap) |
| Envío sin confirmar | fallo de red o página de error del proxy; el reenganche no obtiene respuesta | «Reintentar» con la misma identidad (el servidor deduplica); sin «Recuperar mensaje», porque un envío nuevo podría ejecutarse dos veces |
| Envío no registrado | reenganche con 404, o negativa previa a procesarlo (429 del limitador, sesión o CSRF caducados, redirección al login) | Motivo corto («Demasiados mensajes seguidos», «La sesión ya no es válida»), «Reintentar» y «Recuperar mensaje»; el adjunto queda «No enviado» |
| Conexión perdida / no disponible | reattach agotado / 404 tras recargar | «Comprobar estado» nunca repite la petición |
| Recarga con petición viva | `notice.kind=live` | Se reengancha desde `after=0`, sin enviar |
| Página restaurada (bfcache) | `pageshow` persistida | Se reengancha ocupando el compositor; una subida cortada al ocultar la página vuelve como no registrada si el servidor no la conoce |

## Ejecución del agente

| Estado | Fuente | Representación |
| --- | --- | --- |
| Cabecera | `run.status`, `delivery`, último paso | Trace: icono de estado + paso actual + medidas registradas |
| Pasos | eventos agrupados por `kind`, herramientas, intervalos | Detalle plegable; abierto mientras trabaja salvo espera de decisión |
| Skill activada | `skill.activated` (deduplicada por revisión/instalación/alias) | Aviso pequeño junto al turno, sin foco; también en actividad |
| Texto público | `text.delta`/`text.snapshot` por `message_id`/offset UTF-8 | Segmentos; hueco → snapshot autorizado |
| Espera de decisión | `visual_pending`, `approval_pending`, exportación | Visible fuera del plegable, con la acción |
| Fallo, parcial, incierto | `result.error`, `delivery.status`, `interrupted`, `outcome_unknown` | Visible siempre; no se oculta en detalles |
| Entregables | `artifacts`/`current_revision` + `delivery` | Tarjeta compacta: nombre, tipo, tamaño si existe; revisión y comprobaciones al desplegar. Vista previa/descarga/editar sólo cuando el servidor la serviría (`file_continuity.delivered`: en un recibo completo o parcial, o, sin recibo, con la ejecución completada); antes, «Archivo pendiente de entrega verificada» |
| Revocado | 404/`revoked` | Se retiran texto, tarjetas, recibos, avisos, «Reanudar» y la petición interpretada; acción «Actualizar estado» |
| Reanudar / detener | `resumable`, `cancel_url` | Acciones en el propio turno |
| Uso y coste | `receipt.total`, llamadas | Sólo bajo demanda; desconocido ≠ 0 |

## Visor

Lateral 480–640 px desde 1100 px, modal por debajo; pestañas Vista previa
(iframe `sandbox` sin permisos, `srcdoc` saneado por el servidor) y Código; descarga
original; selector de revisión; validación de ID, hash y revisión; foco inicial y
retorno; Escape cierra. Visor de páginas/hojas para entregables de documento.
