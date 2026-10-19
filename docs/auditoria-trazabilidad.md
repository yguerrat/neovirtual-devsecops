# Matriz de trazabilidad: hallazgo → control → evidencia

Cada hallazgo de la auditoría interna de NeoVirtual se cubre con un control concreto y deja una evidencia verificable en cada build.

## 1. Falta de pruebas de seguridad automatizadas

| Riesgo | Control | Etapa del pipeline | Evidencia archivada | ¿Bloquea? |
|---|---|---|---|---|
| Secretos en el código | Gitleaks | Secretos | `reports/gitleaks.json` | Sí |
| Vulnerabilidades en el código propio (SQLi, debug, binds inseguros) | Bandit (SAST), severidad ≥ media | SAST | `reports/bandit.json` | Sí |
| Regresiones de seguridad (SQLi, XSS, CSRF, IDOR, RBAC, MFA, bloqueo) | 29 pruebas pytest, cobertura ≥ 80 % (hoy ~97 %) | Pruebas de seguridad | `reports/junit.xml`, `reports/coverage.xml` | Sí |
| Vulnerabilidades en la imagen | Trivy, HIGH/CRITICAL con parche | Escaneo de imagen | `reports/trivy.json` | Sí |
| Fallas visibles en la app corriendo (cabeceras, cookies) | OWASP ZAP baseline | DAST | `reports/zap-report.html/json` | No (UNSTABLE) |

## 2. Gestión deficiente de dependencias

| Riesgo | Control | Evidencia |
|---|---|---|
| Versiones con CVE conocidos | `pip-audit` rompe el build | `reports/pip-audit.json` |
| Versiones flotantes → builds no reproducibles | Todo fijado (`==`) y base `python:3.12-slim` | `requirements.txt`, `Dockerfile` |
| Actualizaciones que nadie hace | Dependabot semanal (pip + Docker) | `.github/dependabot.yml` |
| No saber qué componentes lleva cada release | SBOM CycloneDX | `reports/sbom.cdx.json` |

Caso real durante la construcción de este repo: la primera versión fijada (`Flask 3.1.1`, `Werkzeug 3.1.3`) fue rechazada por `pip-audit` con 5 vulnerabilidades y se actualizó a `3.1.3` / `3.1.9`. Es exactamente la compuerta funcionando.

## 3. Documentación y trazabilidad insuficientes

| Necesidad de auditoría | Control |
|---|---|
| ¿Qué commit está en producción? | `reports/build-info.json` (build, commit, rama, imagen, fecha UTC) |
| ¿Qué imagen corre y de dónde viene? | Etiquetas OCI `org.opencontainers.image.revision` y `ci.build-number`; tag `taskmanager-secure:<BUILD_NUMBER>` |
| ¿Qué pruebas se ejecutaron y con qué resultado? | JUnit publicado en Jenkins + artefactos con huella (`fingerprint`) |
| ¿Quién aprobó qué? | Historial Git + builds conservados (últimos 20) |
| ¿Qué hacer ante un incidente? | [SECURITY.md](../SECURITY.md) |

## 4. Monitorización inadecuada

| Capacidad | Implementación |
|---|---|
| Detectar ataques de fuerza bruta | Eventos JSON `login_failure`, `account_locked`, `login_blocked_locked_account` |
| Detectar manipulación | `csrf_rejected`, `login_invalid_input` (payloads SQLi), `admin_access_denied` |
| Disponibilidad | `/health` + `HEALTHCHECK` de Docker + stage *Smoke test* + `--restart unless-stopped` |
| Integración con SIEM | Una línea JSON por evento en stdout (listo para Loki/ELK/Splunk) |

Ejemplo de evento:

```json
{"ts": "2026-10-19T00:40:46Z", "event": "login_failure", "ip": "172.19.0.1", "username": "admin"}
```

Consulta rápida para detectar fuerza bruta:

```bash
docker logs taskmanager-secure 2>&1 | grep '"login_failure"' | grep -o '"ip": "[^"]*"' | sort | uniq -c | sort -rn
```

## Comparación medida sobre las dos apps

| Herramienta | Sin DevSecOps | Con DevSecOps |
|---|---|---|
| Bandit | 2 hallazgos (1 alto: `debug=True`, 1 medio: SQL por concatenación) | 0 |
| pip-audit | Múltiples CVE (Flask 2.0.1, Werkzeug 2.0.1, Jinja2 3.0.1) | 0 |
| Trivy (HIGH+CRITICAL con parche) | 2008 en SO + 6 en paquetes Python | 0 |
| Pruebas automáticas | 0 | 29 (≈97 % cobertura) |
| ZAP baseline | No ejecutado | 0 FAIL, 2 avisos informativos |
| Usuario del contenedor | root | uid 10001, FS de solo lectura, sin capabilities |
