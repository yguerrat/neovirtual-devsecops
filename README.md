# NeoVirtual – DevSecOps: sin vs. con seguridad en el pipeline

Monorepo de demostración. Contiene **la misma aplicación (gestor de tareas Flask)** desplegada por dos pipelines CI/CD de Jenkins: uno sin prácticas de seguridad y otro con DevSecOps integrado.

```
neovirtual-devsecops/
├── apps/
│   ├── taskmanager-sin-devsecops/   # app vulnerable + pipeline "build y deploy"
│   └── taskmanager-con-devsecops/   # app corregida + pipeline con compuertas de seguridad
├── docs/
│   ├── auditoria-trazabilidad.md    # hallazgos de la auditoría -> control -> evidencia
│   └── demo-ataques.md              # guion para mostrar los ataques en vivo
├── infra/                           # Jenkins listo para el laboratorio (con CLI de Docker)
├── .github/dependabot.yml           # actualización automática de dependencias
├── docker-compose.yml               # levanta ambas apps para comparar
└── SECURITY.md
```

## Hallazgos de la auditoría y cómo se cubren

| Hallazgo de la auditoría | Sin DevSecOps | Con DevSecOps |
|---|---|---|
| Sin pruebas de seguridad automatizadas | Etapa *Test* vacía | Gitleaks (secretos), Bandit (SAST), 29 pruebas de seguridad con cobertura ≥ 80 %, Trivy (imagen), OWASP ZAP (DAST) |
| Gestión deficiente de dependencias | Versiones antiguas con CVE, sin revisión | Versiones fijadas, `pip-audit` rompe el build, Trivy, Dependabot |
| Documentación y trazabilidad insuficientes | Ninguna | Reportes archivados por build, SBOM CycloneDX, `build-info.json` (build ↔ commit ↔ imagen), etiquetas OCI en la imagen |
| Monitorización inadecuada | Sin logs de seguridad ni healthcheck | Eventos de seguridad en JSON, `/health` + `HEALTHCHECK`, smoke test post-deploy |

Detalle completo en [docs/auditoria-trazabilidad.md](docs/auditoria-trazabilidad.md).


**Para la clase y los alumnos:** abre [docs/clase-interactiva.html](docs/clase-interactiva.html) en el navegador (no necesita servidor). Es la guía completa del laboratorio: 11 pasos con comandos para copiar (Windows o Mac/Linux), el campo para poner tu propio repositorio, un simulador de ataques contra ambas versiones, un simulador que rompe el pipeline a propósito, la evidencia de auditoría, ayuda para los errores comunes y un cuestionario. Tiene modo proyección y navega con las flechas ← →.

## Las dos aplicaciones

**`taskmanager-sin-devsecops`** (puerto 5001) – el código original vulnerable más un entorno típico de "así lo hacíamos":
inyección SQL en el login, borrado por `GET` sin CSRF, IDOR (cualquier usuario borra tareas ajenas), hash SHA-256 sin sal, sin MFA ni bloqueo de cuenta, `debug=True` (consola Werkzeug expuesta), dependencias antiguas con CVE, imagen `python:3.9` completa corriendo como root.

**`taskmanager-con-devsecops`** (puerto 5002) – la versión corregida y su pipeline:
consultas parametrizadas, validación por lista blanca, CSRF, MFA TOTP, hash con sal (scrypt), bloqueo progresivo, RBAC, verificación de propiedad, cabeceras de seguridad, sin credenciales en el código, imagen multi-etapa no-root, solo lectura y sin capabilities.

## Probar localmente (sin Jenkins)

```bash
cp .env.example .env          # y edita los valores
docker compose up -d --build
```

- Vulnerable: http://localhost:5001 (`admin` / `password`)
- Segura: http://localhost:5002 (requiere contraseña **y** código MFA)

Los secretos MFA de la app segura se imprimen una vez al crear la BD:

```bash
docker logs taskmanager-secure | grep MFA
```

Pruebas de la app segura (necesita Python 3.12, o usa Docker):

```bash
cd apps/taskmanager-con-devsecops
pip install -r requirements-dev.txt
pytest --cov=app --cov=create_db --cov-fail-under=80
```

## Pipelines en Jenkins

El repositorio incluye un Jenkins listo para el laboratorio (`infra/`): imagen oficial con el CLI de Docker y el socket del equipo montado. Debe llamarse `jenkins`, porque el pipeline seguro usa `--volumes-from jenkins`.

```bash
docker compose -f infra/docker-compose.jenkins.yml up -d --build
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

Abre http://localhost:8080, pega la clave e instala los plugins sugeridos.

> Si ya tienes otro Jenkins, necesita el CLI de Docker (paquete `docker-cli`; en Debian 13 el paquete `docker.io` no lo trae) y el socket montado. Compruébalo con `docker exec jenkins docker --version`.

Jenkins clona desde una URL y no ve tu carpeta local, así que primero inicializa el repo y súbelo al repositorio del laboratorio:

```bash
git init -b main && git add -A && git commit -m "Proyecto inicial"
git remote add origin https://github.com/yasserguerrat-hub/neovirtual-devsecops.git
git push -u origin main
```

Los jobs son de tipo **Pipeline script from SCM** apuntando a tu repositorio, rama `main`, y cambian solo el *Script Path*:

| Job | Script Path |
|---|---|
| `taskmanager-sin-devsecops` | `apps/taskmanager-sin-devsecops/Jenkinsfile` |
| `taskmanager-con-devsecops` | `apps/taskmanager-con-devsecops/Jenkinsfile` |

Para el job **con** DevSecOps crea antes tres credenciales *Secret text* (Manage Jenkins → Credentials → Global):

| ID | Valor |
|---|---|
| `taskmanager-secret-key` | cadena aleatoria larga (`openssl rand -hex 32`) |
| `taskmanager-admin-pw` | contraseña del admin |
| `taskmanager-user-pw` | contraseña del usuario |

Etapas del pipeline seguro: Trazabilidad → Secretos → SAST → SCA → Pruebas → Build → Trivy + SBOM → Deploy → Smoke test → DAST. Las herramientas corren en contenedores con versión fija, así que Jenkins no necesita instalar nada. Todo reporte queda archivado en el build (`apps/.../reports/`).

## Notas de alcance

- Es un laboratorio: la app usa SQLite y HTTP. En producción irían una base de datos gestionada, HTTPS (`COOKIE_SECURE=true`) y un gestor de secretos.
- ZAP se ejecuta en modo *baseline* (pasivo) y no autenticado; informa pero no bloquea el despliegue. Los demás controles sí bloquean.
