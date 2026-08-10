# ADR 0001: almacenamiento BYOK con Supabase Vault

## Estado

Aceptada para MVP.

## Contexto

El producto requiere BYOK para que los usuarios continuen investigando IOCs tras agotar su cuota gratuita. Las claves API son secretos de alto impacto: no deben almacenarse en texto plano ni exponerse al frontend.

## Decision

Usar Supabase Vault para almacenar los valores de claves API cifrados. La tabla `public.user_api_keys` solo guarda:

- `vault_secret_id`
- proveedor
- etiqueta visible
- ultimos 4 caracteres
- estado y metadatos no sensibles

El backend usara una credencial server-side para resolver secretos cuando deba invocar servidores MCP con BYOK.

## Consecuencias

- Las consultas normales desde el cliente no pueden leer secretos.
- Hay que proteger acceso a `vault.decrypted_secrets`.
- Las funciones RPC que reciban claves deben evitar logs con parametros sensibles.
- La rotacion/revocacion de secretos sera una historia explicita posterior.

