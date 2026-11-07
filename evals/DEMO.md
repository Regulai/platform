# Demo Community aislada

Desde la raíz del repositorio:

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py run_demo --settings=regulai.demo_settings
```

Abrir `http://127.0.0.1:8001/login/`. Usuario: `community-demo`. Contraseña pública sintética: `community-demo-only`.

El comando usa exclusivamente `regulai/community-demo.sqlite3`, crea las migraciones y siembra la identidad sintética una vez. Un dato existente que no coincide con el fixture se conserva y provoca un error; no se reinician conversaciones ni contraseñas. No usa la base normal ni sus credenciales. El servidor escucha solo en loopback y desactiva el autoreloader. `--seed-only` prepara los datos sin iniciar el servidor; `--port 8002` cambia únicamente el puerto local.

Durante este comando se simulan la generación y el HTTP de Jev y se bloquea cualquier otra petición HTTP o conexión saliente. Los parches se retiran al salir. El inicio normal del servidor no instala estas simulaciones. Las cookies y archivos de la demo también tienen nombres y ubicaciones distintos. El banner muestra «DEMO OFFLINE — fallo simulado».

Recorridos:

1. En Chat, seleccionar **Synthetic economy** y enviar `Devuelve el saludo Hola.`. La ficha registra una generación económica y sus comprobaciones.
2. En una conversación nueva, enviar `SYNTHETIC_SECRET_DEMO`. YARA lo bloquea antes de cualquier llamada simulada.
3. En otra conversación nueva, adjuntar `evals/documents/demo-contract.txt`, seleccionar **Synthetic economy** y preguntar `¿Cuál es el precio del contrato?`. El fixture económico contesta erróneamente 900 euros; el juez prefijado lo rechaza. El segundo intento fuerte devuelve 10 euros con una cita resoluble y se verifica antes de mostrarlo.

Las fuentes distintas del contrato conocido solicitan aclaración en esta demo. Otros mensajes generales usan el saludo sintético. Estos recorridos prueban controles y estados, no precisión real del juez ni superioridad de un proveedor. Para recuperar el modo normal, terminar el proceso con Ctrl+C e iniciar el servidor habitual con su configuración normal; sus datos se conservan.
