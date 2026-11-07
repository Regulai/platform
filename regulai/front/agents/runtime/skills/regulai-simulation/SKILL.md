---
name: regulai-simulation
description: Simula paseos aleatorios finitos en dos o tres dimensiones con semilla, recuentos y comprobación reproducibles.
license: BSL-1.1 (LICENSE.txt)
compatibility: Perfil profesional con execute autorizado, Python y NumPy 2.5.3 instalados; no instala dependencias ni usa red.
---

# Paseos aleatorios reproducibles

Usa esta skill cuando se pida una simulación de retorno al origen en dimensiones
2 y/o 3. Es una estimación de horizonte finito: no prueba recurrencia ni
transiencia asintótica. No cambies dimensiones, semilla, caminantes, pasos ni
precisión pedidos. No añadas gráfico, CSV, otras dimensiones o demostración
teórica si no se solicitan. Para otros modelos explica el alcance disponible.

Lee [el modelo y sus límites](references/model.md). El programa revisado ya está
en `scripts/random_walk.py`: no lo regeneres, copies ni optimices por turno.
Escribe únicamente el pequeño JSON de parámetros en `/workspace` y usa las
herramientas de ejecución autorizadas. Instalar la skill no concede execute.
Si NumPy no está disponible, informa del requisito; no ejecutes pip ni npm.

Ejemplo del caso de regresión autorizado, sin crear entregables adicionales:

```json
{"dimensions":[2,3],"seed":20261016,"walkers":2000,"steps":2000,"horizons":[2000]}
```

```text
python /skills/<alias>/scripts/random_walk.py run --spec /workspace/spec.json --out /workspace/result.json
python /skills/<alias>/scripts/random_walk.py check /workspace/result.json
```

Sustituye `<alias>` por la ruta virtual inmutable proporcionada por el servidor.
No supongas que sea el nombre original del paquete. `run` crea el archivo de
resultado exclusivamente: si existe, usa otra ruta autorizada, no lo borres.
Ambos comandos devuelven JSON acotado. Un código de salida distinto de cero es
fallo/cancelación, nunca éxito. Presenta recuento, denominador y fracción para
cada horizonte solicitado, semilla y versión NumPy. El archivo es un resultado
de trabajo; solo publícalo si el usuario pide descargarlo. No es necesario
publicar un archivo para responder cifras en el chat.

Un `check` correcto acredita invariantes y reproducción en el mismo entorno,
no calidad de un proveedor LLM ni equivalencia entre versiones de NumPy. No
repitas la simulación salvo fallo concreto, parámetros nuevos o petición expresa.
