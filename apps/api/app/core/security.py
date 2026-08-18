from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    user_id: str
    org_id: str
    email: str | None = None
    roles: tuple[str, ...] = ("analyst",)


def hash_api_key(key: str) -> str:
    """Hash a service API key for storage; the plaintext is never persisted."""
    return sha256(("huntdeck:" + key).encode()).hexdigest()


def _resolve_api_key_user(
    api_key: str,
    org_id: str,
) -> CurrentUser | None:
    """Resolve a service API key (X-API-Key / Bearer) to a user, or None.

    Uses the local store so service tokens work without Supabase.
    """
    from app.domain.quota.service import get_quota_store

    store = get_quota_store()
    bound_org = store.verify_api_key(hash_api_key(api_key))
    if bound_org is None:
        return None
    return CurrentUser(
        user_id="svc-api-key",
        org_id=org_id if org_id != "dev-org" else bound_org,
        email="svc@api",
        roles=("service",),
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    x_org_id: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    org_id = _normalize_org_id(x_org_id)

    if x_api_key:
        user = _resolve_api_key_user(x_api_key, org_id)
        if user is not None:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    if not settings.supabase_jwt_secret:
        return CurrentUser(user_id="dev-user", org_id=org_id, email="dev@local")

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
        )

    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token.",
        ) from exc

    subject = claims.get("sub")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token has no subject.",
        )

    return CurrentUser(
        user_id=str(subject),
        org_id=org_id,
        email=claims.get("email"),
        roles=tuple(claims.get("app_metadata", {}).get("roles", ["analyst"])),
    )


def _normalize_org_id(value: str | None) -> str:
    if value is None or not value.strip():
        return "dev-org"
    try:
        return str(UUID(value))
    except ValueError:
        return value.strip()
