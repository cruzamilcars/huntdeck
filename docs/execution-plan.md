# Plan de ejecucion por sprints

## Fase 0 - Criterios y referencias

Referencias primarias usadas para este plan:

- Next.js App Router: usar `src/app` como raiz de rutas y convenciones de filesystem.
- FastAPI: separar una aplicacion grande con `APIRouter` por dominios/rutas.
- Supabase: activar RLS en tablas expuestas y escribir politicas con `to authenticated` y `(select auth.uid())`.
- Supabase Vault: almacenar secretos cifrados con `vault.create_secret()` y exponer solo referencias no sensibles en tablas de negocio.

Guardas:

- No guardar claves API BYOK en tablas `public`.
- No exponer `vault.decrypted_secrets` a `anon` ni `authenticated`.
- No crear integraciones API rigidas en el dominio OSINT; el backend debe depender de adaptadores MCP.
- No implementar UI hasta cerrar contratos de API y JSON unificado.

## Sprint 1 - Estructura y datos

Estado: completado.

Entregables:

- Monorepo con `apps/web`, `apps/api`, `packages/shared`, `supabase`, `docs`, `infra`.
- Migracion SQL inicial con organizaciones, perfiles, RBAC, historial, cuota diaria y BYOK.
- Politicas RLS base.
- Funcion RPC inicial para crear referencias BYOK usando Vault.

Verificacion:

- Revisar existencia de carpetas y archivos base.
- Revisar sintaxis SQL con Supabase CLI o `psql` en el siguiente paso de entorno.

## Sprint 2 - Backend FastAPI + IOC parser + MCP simulado

Estado: completado.

Entregables:

- Servidor FastAPI con CORS, security headers y rate limiting.
- Parseo de IOCs por regex: IPv4, IPv6, dominio, URL, MD5, SHA-1, SHA-256, email y telefono.
- Orquestador agentico con cliente MCP (protocolo) y proveedores simulados.
- Respuesta normalizada a JSON tactico unico (`POST /api/v1/investigations`).
- Tests unitarios (parser, quota, orquestador) e integracion (API, headers).

Verificacion:

- `pytest` en `apps/api`.
- Casos positivos/negativos por tipo IOC.
- Respuesta JSON incluye modulos: reputacion, geolocalizacion, grafo, comunidad, MITRE/NIST/ISO.

## Sprint 3 - Frontend brutalista Next.js

Estado: completado.

Entregables:

- Next.js con TypeScript y Tailwind en `apps/web`.
- Tema oscuro estricto: cero border-radius, monospace, alto contraste.
- Pantalla `/investigate` con barra terminal, paneles Reputacion, Geolocalizacion,
  Grafo, Informes Comunitarios y mapeos MITRE/NIST/ISO.
- Exportacion PDF/CSV cliente (jsPDF).
- Cliente API tipado contra FastAPI.

Verificacion:

- Build Next.js.
- Screenshot desktop/mobile.
- Validar no-overlap de textos y estados vacio/cargando/error.

## Sprint 4 - Supabase Auth, RBAC y cuota BYOK

Estado: completado (core). La autenticacion es opcional: sin env vars el backend
opera en modo desarrollador anonimo.

Entregables:

- Rutas `/login` y `/register` con Supabase Auth en el frontend.
- Cliente Supabase browser/server en `apps/web/src/lib/supabase/`.
- Verificacion JWT (HS256, audience `authenticated`) en FastAPI.
- Servicio de cuota diaria con fallback BYOK.
- Auditoria por `X-Org-Id` cuando el usuario tiene `default_org_id`.

Verificacion:

- Usuario sin sesion no puede consultar.
- Usuario Community puede usar 10 consultas/dia.
- Usuario con BYOK puede continuar tras cuota agotada.
- Usuario no puede ver datos de otra organizacion.

## Sprint 5 - Hardening y preparacion SaaS

Estado: completado (nucleo). Pendientes con fecha futura: reglas de retencion de
historial en produccion y persistencia real en Supabase desde el backend.

Entregables:

- Rate limiting por IP en middleware.
- Security headers, CORS limitado y validacion estricta Pydantic.
- Redaccion de claves en errores (BYOK solo via Vault).
- Exportacion PDF/CSV desde frontend.

Verificacion:

- Tests backend/frontend.
- Reglas RLS revisadas.
- No hay secretos en logs ni en tablas `public`.

