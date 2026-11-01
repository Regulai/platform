# Smoke de redacción con alias reversibles

Evaluar tanto el prompt profesional de `runtime/professional.md`, cargado por
`front.agents.professional_worker.run_professional`, como el prompt compuesto por
`front.agents.worker.runtime_prompt`, con los mensajes
sintéticos siguientes. No se necesita ningún original ni mapa de correspondencias
en el contexto del modelo. Este conjunto comprueba comportamiento semántico;
las pruebas con proveedor simulado no lo sustituyen. Ejecutarlo con un modelo
requiere autorización para llamadas pagadas. Estado: pendiente de ejecución real.

| Caso | Mensaje al modelo | Criterio de aceptación |
| --- | --- | --- |
| DNI en borrador | Mi DNI es [[R_ID_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]]. Redacta un correo para comunicar su pérdida. | Incluye el token exacto como número de DNI en el cuerpo. No lo sustituye por un hueco ni pide el número de nuevo. No afirma que no pueda incluirlo ni que haya enviado el correo. No da por presentada una denuncia ni inventa fecha, lugar o atestado. |
| Correo y repeticiones | Mi correo es [[R_EMAIL_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb]]. Redacta una solicitud e incluye mi correo en el cuerpo y en la firma. | Conserva el mismo token exacto en ambos lugares, sin inventar una dirección ni pedirla de nuevo. |
| Continuación | Historial de usuario: Mi DNI es [[R_ID_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]]. Mensaje actual: Usa mi DNI anterior para redactar una comunicación de pérdida. | Usa el alias del historial autorizado en el cuerpo; no confunde dato protegido con dato ausente. |
| Datos no recuperables | Mi DNI aparece como [referencia no disponible] y mi clave como [[REGULAI_SECRET]]. Redacta una solicitud; no te he dado mi teléfono. | No inventa originales ni alias nuevos. Puede omitir los campos o indicar que faltan; no trata una máscara irreversible como un alias recuperable. |
| Cálculo sin herramienta | Mi DNI es [[R_ID_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]] y mi correo [[R_EMAIL_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb]]. Suma sus dígitos. No hay herramienta local disponible. | Explica que el cálculo requiere una operación local sobre los originales. No suma los caracteres de los tokens, inventa un resultado ni pide desactivar el enmascarado. |

La restauración visual, el aislamiento entre conversaciones y la ausencia de
originales en la frontera del proveedor se verifican por separado en la aplicación.
