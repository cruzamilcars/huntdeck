# Arquitectura de carpetas

```text
osint-mcp-hub/
  apps/
    web/                         # Next.js App Router
      src/
        app/
          (auth)/login/           # Rutas de autenticacion
          (dashboard)/investigate/ # Experiencia principal IOC
        components/
          layout/                 # Shell, nav, paneles base
          search/                 # Barra terminal de IOC
          results/                # Modulos tacticos de resultados
          export/                 # PDF/CSV
        lib/
          api/                    # Cliente FastAPI
          supabase/               # Cliente Supabase browser/server
        styles/                   # Tailwind/theme brutalista
    api/                          # FastAPI
      app/
        api/v1/routes/            # Routers HTTP
        agents/mcp/               # Cliente MCP y proveedores simulados/reales
        core/                     # Config, seguridad, logging
        db/                       # Acceso Supabase/Postgres
        domain/
          ioc/                    # Parseo, tipos y normalizacion IOC
          quota/                  # Freemium/BYOK
          reports/                # Export/report contracts
        schemas/                  # Pydantic DTOs
        services/                 # Casos de uso: orquestacion, persistencia
      tests/
        unit/
        integration/
  packages/
    shared/src/                   # Tipos/contratos compartidos cuando aplique
  supabase/
    migrations/                   # SQL versionado
    policies/                     # Politicas adicionales si se separan
    seed/                         # Datos no sensibles de desarrollo
  docs/
    adr/                          # Decisiones arquitectonicas
  infra/
    docker/                       # Compose/Dockerfiles futuros
    deploy/                       # IaC/deploy futuro
```

## Decisiones iniciales

1. El backend es el unico responsable de la orquestacion MCP.
2. El frontend nunca recibe claves API BYOK ni secretos de proveedores.
3. Supabase Auth mantiene identidades; `public.profiles` agrega datos de producto.
4. RBAC se modela por organizacion para soportar SOCs y equipos Red/Blue Team.
5. El historial de investigaciones se guarda por organizacion, no solo por usuario.
6. Las claves BYOK se guardan en Vault y `public.user_api_keys` solo conserva referencias.
7. El limite Community se controla por `daily_usage`, con default de 10 consultas gratis/dia por organizacion/usuario.

## Contrato tactico de resultados

El backend devolvera un JSON consolidado con estas secciones minimas:

```json
{
  "ioc": {
    "raw": "string",
    "normalized": "string",
    "type": "ipv4 | ipv6 | domain | url | md5 | sha1 | sha256 | email | phone"
  },
  "risk": {
    "score": 0,
    "severity": "unknown | low | medium | high | critical"
  },
  "modules": {
    "reputation": {},
    "geolocation": {},
    "relationship_graph": {},
    "community_reports": {}
  },
  "mappings": {
    "mitre_attack": [],
    "nist": [],
    "iso": []
  },
  "sources": []
}
```

