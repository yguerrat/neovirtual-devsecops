# Política de seguridad

Este repositorio es un laboratorio educativo. `apps/taskmanager-sin-devsecops` es **vulnerable a propósito**: no lo despliegues fuera de un entorno aislado.

Para reportar un problema en `apps/taskmanager-con-devsecops`, abre un issue privado o contacta al equipo de seguridad de NeoVirtual indicando versión, pasos para reproducirlo e impacto. Se confirma la recepción en 3 días hábiles.

## Respuesta a incidentes (resumen)

1. **Detectar**: alertas sobre eventos `account_locked`, `login_failure` repetidos, `csrf_rejected` y `admin_access_denied` en los logs JSON.
2. **Contener**: `docker stop taskmanager-secure`; rotar `SECRET_KEY` (invalida todas las sesiones) y las credenciales afectadas.
3. **Erradicar y recuperar**: corregir, volver a ejecutar el pipeline (las compuertas validan la corrección) y redesplegar.
4. **Registrar**: el build archivado deja commit, imagen, reportes y SBOM como evidencia.
