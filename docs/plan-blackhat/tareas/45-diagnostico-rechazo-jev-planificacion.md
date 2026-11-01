# 45. Diagnóstico del rechazo semántico en planificación

Estado: causa observada en reproducción real; el usuario solicita retirar la verificación final del chat de texto (tarea 46). Falsos positivos del enmascarador pendientes.
Blocked by: ninguno para el cambio solicitado en la tarea 46.

## Evidencia

- `2ca6617f-de3e-4f74-89e5-be6574b51387`: Pro completo, controles locales correctos,
  Jev omisión 0,15 y contradicción/afirmación sin respaldo 0,68.
- `7fb0e19d-fca5-4cad-a242-dfdcc04209f1`: modo de límites del proveedor activo,
  Pro completo, controles locales correctos, Jev omisión 0,20 y contradicción 0,72.
- Con umbral de verificación 0,8 se acepta un fallo <= 0,2. El segundo intento falla
  por contradicción, no por omisión, generación truncada, tiempo ni bloqueo YARA.
- La respuesta rechazada no se guarda como Response ni Message. No se puede
  concluir que el rechazo sea un falso positivo sin ver el texto evaluado.

## Trabajo local

Se muestran las señales y el umbral en los recibos existentes y se guardan códigos
de motivos en los nuevos. No se modifica el umbral, la rúbrica ni el modo enforce.
32 pruebas de interfaz, dificultad y diagnóstico: OK, 11,423 s.

Reproducción del mismo envío preparada en `.claude/diagnose_current_judge.py`:
requiere `--real`, usa el mismo pipeline y captura solo estado enmascarado, preguntas,
respuestas del juez y recibo. No captura cabeceras, claves ni razonamiento interno.
Guardó un informe local ignorado por Git para comparar la respuesta realmente
evaluada. El usuario autorizó hasta cuatro llamadas y se ejecutaron tres.

Referencia matemática para analizar la salida: primer caso mínimo 5 h
(A 0–3, B 3–5, C 0–4; cota A+B=5); segundo caso mínimo 6 h
(A 0–3, C 0–4, B 4–6; cota C+B=6). No es una respuesta recuperada de Pro.

## Reproducción autorizada y resultado

Recibo `e241ab53-34a6-474b-82a3-2e6b94aa6570`: tres llamadas externas,
coste registrado 0,012566160 USD, parcialmente estimado. Pro completo; Jev omisión
0,15 y contradicción 0,49. Informe local conservado en
`.claude/judge-diagnostic-e241ab53-34a6-474b-82a3-2e6b94aa6570.json`.

Se observa que el detector local sustituye «Tengo», «A» y «A. Dispongo» en la
pregunta, además de letras y encabezados en la respuesta. La respuesta evaluada
contiene horarios y resultados 5/6 h, pero también dependencias y tablas alteradas
por marcadores de privacidad. No es evidencia suficiente para culpar únicamente
a la rúbrica de Jev.

Se probó localmente `es_core_news_sm` 3.8.0 (wheel oficial y checksum verificado).
También detecta incorrectamente «A» y «A. Dispongo». No se integró ni se añadieron
excepciones improvisadas; el paquete experimental se desinstaló al cambiar el usuario
el alcance hacia retirar el juez final. No hay cambios al detector ni a dependencias.
La cuarta llamada autorizada no se utilizó. Se eliminó el script temporal de reproducción.
