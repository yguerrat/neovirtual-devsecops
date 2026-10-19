# Guion de demostración

Levanta ambas apps (`docker compose up -d --build`, ver README). Cada ataque se prueba primero contra la **vulnerable** (5001) y luego contra la **segura** (5002).

> Solo contra estos contenedores locales de laboratorio.

## 1. Inyección SQL en el login

Vulnerable: en http://localhost:5001/login
- Usuario: `admin`
- Contraseña: `' OR '1'='1`
- Resultado: entras al panel sin conocer la contraseña. La consulta resultante queda impresa en el log del contenedor.

Segura: mismo payload en http://localhost:5002/login → `400 Datos invalidos` (lista blanca de usuario) o `401` (consulta parametrizada). En los logs aparece `login_invalid_input`.

## 2. Borrado por GET sin CSRF + IDOR

Vulnerable: con sesión iniciada, abre `http://localhost:5001/delete_task/1`. Borra la tarea con un simple enlace (un atacante podría incrustarlo en una imagen o correo) y no valida que la tarea sea tuya.

Segura: la misma URL devuelve `405`; el `POST` exige token CSRF y filtra por `user_id`, así que no puedes borrar tareas ajenas.

## 3. Consola de depuración expuesta

Vulnerable: http://localhost:5001/console → consola interactiva de Werkzeug (ejecución de código, protegida solo por un PIN).

Segura: `404`. Corre con gunicorn y sin debug.

## 4. Autenticación débil

- Vulnerable: SHA-256 sin sal, sin MFA, intentos ilimitados.
- Segura: scrypt con sal, MFA TOTP obligatorio, bloqueo tras 5 fallos (5 min). Prueba 5 contraseñas malas y mira `account_locked` en `docker logs taskmanager-secure`.

Obtener el código MFA para entrar a la segura: toma el secreto con `docker logs taskmanager-secure | grep MFA` y cárgalo en una app TOTP (Google Authenticator, Authy…), o genera el código con:

```bash
docker exec taskmanager-secure python -c "import pyotp,sqlite3;print(pyotp.TOTP(sqlite3.connect('/data/database.db').execute(\"select mfa_secret from users where username='user'\").fetchone()[0]).now())"
```

## 5. Lo que ve el pipeline

Ejecuta ambos jobs y compara:

- **Sin DevSecOps**: verde en 1 minuto, con SQLi, CVE y root en producción.
- **Con DevSecOps**: si reintroduces la vulnerabilidad (por ejemplo, vuelve a concatenar SQL en `app.py`, o baja `Flask` a `2.0.1` en `requirements.txt`), el build **falla** en SAST/SCA/Pruebas antes de llegar a Deploy.
