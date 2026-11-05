# Acceso privado desde la red

Esta configuración mantiene la aplicación accesible solo dentro de la red privada de Tailscale. El servidor escucha en `127.0.0.1`; no abras el puerto 3000 en el router ni actives Tailscale Funnel.

## Preparar el equipo servidor

1. Instala Node.js 20.6 o posterior y [Tailscale para Windows](https://tailscale.com/download/windows) en la PC que permanecerá encendida.
2. Inicia sesión en Tailscale con la cuenta privada de la tienda.
3. En Tailscale, autoriza únicamente a las dos personas/dispositivos que usarán el sistema. No compartas el equipo servidor con otras cuentas.
4. En la carpeta del proyecto, copia `.env.example` como `.env`:

   ```powershell
   Copy-Item .env.example .env
   ```

5. Edita `.env` y configura nombres de usuario y contraseñas nuevas, únicas y largas (al menos 12 caracteres; se recomienda 20 o más) para `ADMIN_*` y `SECOND_USER_*`. El segundo usuario tiene el rol `vendedor` de forma predeterminada; puede usar `contabilidad` si corresponde.
6. Protege el archivo `.env` y la carpeta `data`: contienen credenciales de inicialización y datos de clientes. No los envíes por correo ni los subas a Git.
7. Inicia el servidor con `start-private-server.cmd` o ejecuta `npm run start:private` desde la carpeta del proyecto. Deja el proceso activo.
8. En una terminal de Tailscale de la PC servidor, configura Serve:

   ```powershell
   tailscale serve --bg 3000
   ```

   En la primera ejecución, sigue las instrucciones para habilitar HTTPS en la red privada de Tailscale. Comprueba el nombre y la URL que muestra `tailscale serve status`.
9. En la segunda PC, instala Tailscale e inicia sesión en la misma red privada. Abre la URL HTTPS mostrada por Tailscale Serve e inicia sesión con la cuenta asignada.

Tailscale Serve es privado para los miembros autorizados de la red Tailscale; no uses `tailscale funnel`. En Windows, desactiva la suspensión automática de la PC servidor y mantenla conectada a energía e internet.

## Iniciar automáticamente

Para que la app arranque cuando inicie Windows, crea una tarea en el Programador de tareas:

- Desencadenador: al iniciar sesión el usuario de Windows que ejecuta la tienda.
- Acción: iniciar el archivo `start-private-server.cmd` del proyecto.
- Configura la tarea para ejecutarse solo con ese usuario y no guardes la contraseña de Windows en el proyecto.

Después de reiniciar, comprueba `http://127.0.0.1:3000/api/health` en la PC servidor y revisa `tailscale serve status`.

## Datos y copias de seguridad

- La base se conserva en `data/inventory.db`. No borres ni reemplaces ese archivo para actualizar la aplicación.
- Antes de actualizar, detén el servidor y copia `data/inventory.db` a una ubicación segura con acceso restringido. Vuelve a iniciarlo después.
- Las copias contienen información personal y comercial; almacénalas en un disco protegido y conserva copias periódicas.
- Si se despliega una copia nueva del proyecto, conserva el `.env` y la base de datos de forma separada y segura.

El servidor de desarrollo puede seguir usando usuarios demo en modo local. Para esta configuración privada, inicia siempre con `npm run start:private`; el modo producción exige un administrador activo y no crea cuentas demo.

## Cambiar una contraseña temporal

Entra con la cuenta temporal y usa **Cambiar contraseña** en la barra superior. Escribe la contraseña actual, luego la nueva (mínimo 12 caracteres) y confírmala. El sistema guarda solo un hash y cierra las sesiones activas de esa cuenta; tendrás que volver a iniciar sesión con la nueva contraseña.

Si todavía no inicializaste la base de producción y prefieres escoger credenciales antes del primer inicio, cambia los valores de `.env`. Una vez creada la cuenta, cambia su contraseña desde la app.

## API administrativa de estado por IMEI

Con una sesión autenticada de administrador o contabilidad, la app permite cambiar el estado administrativo del equipo asociado al código registrado:

- `POST /api/devices/block` con JSON `{"imei":"IMEI_O_SERIE"}` marca el código como bloqueado.
- `POST /api/devices/unblock` con JSON `{"imei":"IMEI_O_SERIE"}` lo marca como activo.

Envía el token de sesión en `Authorization: Bearer <token>`. Ambos cambios son idempotentes. La API solo actualiza el registro de la tienda; no bloquea el dispositivo, la SIM ni el acceso a la red móvil. Para solicitar un bloqueo real de IMEI, contacta a la operadora o autoridad competente y sigue su proceso autorizado.
