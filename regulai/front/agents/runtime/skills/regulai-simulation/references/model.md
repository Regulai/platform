# Modelo, reproducción y límites

Cada caminante parte del origen. En cada paso elige uniformemente uno de los
`2*d` vecinos de la retícula entera, con movimientos ±1 en un solo eje. Se cuenta
cada caminante una sola vez, cuando vuelve al origen después del paso cero.
La fracción acumulada al horizonte h es ese recuento / número de caminantes.
Los retornos solo ocurren en pasos pares y el acumulado nunca decrece.

Se usa `numpy.random.Generator(numpy.random.PCG64(seed))`. Cada dimensión inicia
su propio generador con la misma semilla; el orden de las dimensiones no cambia
su resultado individual. Por paso se hace exactamente una llamada
`integers(0, 2*d, size=walkers, dtype=int64)`, en orden de caminante. El entero k
elige el eje `k//2` y signo `2*(k%2)-1`. El resultado registra algoritmo, versión
NumPy, huella de configuración de compilación, plataforma y forma/orden de
llamadas. La semilla sola no promete igualdad entre compilaciones o versiones.

El estado vivo contiene posiciones `(walkers, d)` y una máscara de retornos;
la memoria es O(caminantes × dimensiones), no O(caminantes × pasos). No se
conservan trayectorias completas. El horizonte por defecto es el paso final;
se pueden pedir como máximo 64 horizontes enteros distintos ordenados, dentro
de `[1, steps]`. El paso cero siempre se excluye.

Contrato de entrada: `dimensions`, `seed`, `walkers`, `steps` y opcional
`horizons`. No se ignoran claves desconocidas, booleanos como enteros ni
dimensiones duplicadas. Dimensiones permitidas: 2 y 3; caminantes 1–20.000;
pasos 1–10.000; máximo total `walkers*steps*len(dimensions)` 100.000.000.
Semilla entera sin signo de 64 bits. Archivo de entrada ≤8 KiB y resultado
≤32 KiB. Plazo local por defecto 10 s, máximo 60 s; se comprueba en cada paso,
antes/después de cada dimensión y antes de publicar el archivo. SIGINT/SIGTERM
cancelan sin publicar un resultado parcial. El runner conserva los límites
superiores de CPU/memoria/tiempo y permisos de archivos del producto.

`check` exige schema, parámetros, versión/huella de entorno y esquema de
resultados exactos, valida rango/paridad/monotonía y vuelve a calcular las
mismas muestras para contrastar todos los recuentos. Una comprobación local
independiente de trayectorias cortas respalda el algoritmo en la suite de
pruebas. Reproducir la misma muestra no aporta observaciones estadísticas
independientes ni reduce la incertidumbre de Monte Carlo.

El caso P1 es d=[2,3], semilla20261016,2.000 caminantes y2.000 pasos. No es el
inventario determinista c09 del corpus P0 ni una reconstrucción de parámetros
históricos del chat6. Solo se compara calidad/coste cuando problema, entorno,
semilla y oráculo son los mismos.
