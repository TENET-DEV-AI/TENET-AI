"""Sign-in log — who opened the console, and when.

The console is a restricted surface, so every successful sign-in is appended to
a small log. Two reasons: an operator can see who has access, and the project
can count sign-ups without a third-party analytics script in the browser.

What is stored, deliberately and only this:

    email, provider (google | password), role, timestamp, day bucket

Nothing else — no IP, no user agent, no prompt content. The console shows a
notice on the sign-in screen, `SIGNIN_LOG_ENABLED=false` turns the whole thing
off, and `docs/signin-log.md` covers retention and the consent question.

Storage degrades rather than fails: Redis when it is up, an in-process store
when it is not (single-process dev, unit tests), and a `recorded: false` answer
when the operator has disabled logging. A sign-in is never blocked by this.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Deque, Dict, List, Literal, Optional, Protocol

from fastapi import APIRouter, Query, Security
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

LOG_KEY = "tenet:signins:log"
ACCOUNTS_KEY = "tenet:signins:accounts"
DAY_KEY = "tenet:signins:day:{day}"
PROVIDER_KEY = "tenet:signins:provider:{provider}"

MAX_LOG_ENTRIES = 5000
DAY_TTL_SECONDS = 400 * 24 * 60 * 60


def _enabled() -> bool:
    return os.getenv("SIGNIN_LOG_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _normalise_email(raw: str) -> str:
    return raw.strip().lower()


class SignInRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, description="Analyst email, as issued by the identity provider")
    provider: Literal["google", "password"] = Field("google", description="How the analyst signed in")
    role: Optional[str] = Field(None, max_length=80, description="Role the console opened with")
    org_domain: Optional[str] = Field(None, max_length=120, description="Workspace domain, when known")


class SignInResponse(BaseModel):
    recorded: bool
    storage: Literal["redis", "memory", "none"]


class DayCount(BaseModel):
    date: str
    count: int


class SignInStats(BaseModel):
    window_days: int
    total: int
    unique_accounts: int
    by_day: List[DayCount]
    by_provider: Dict[str, int]
    last_signin: Optional[Dict[str, Any]] = None


class Store(Protocol):
    """What the router needs from a backend."""

    async def append(self, record: Dict[str, Any]) -> bool:
        """Add one sign-in. Returns False when the write did not land."""
        ...

    async def stats(self, days: int) -> SignInStats:
        """Counts for the last `days` days."""
        ...


class MemoryStore:
    """Process-local fallback. Bounded, and lost on restart — good enough for dev."""

    def __init__(self) -> None:
        self._log: Deque[Dict[str, Any]] = deque(maxlen=MAX_LOG_ENTRIES)
        self._accounts: set[str] = set()
        self._days: Counter[str] = Counter()
        self._providers: Counter[str] = Counter()

    async def append(self, record: Dict[str, Any]) -> bool:
        self._log.append(record)
        self._accounts.add(record["email"])
        self._days[record["day"]] += 1
        self._providers[record["provider"]] += 1
        return True

    async def stats(self, days: int) -> SignInStats:
        since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        by_day = [DayCount(date=d, count=c) for d, c in sorted(self._days.items()) if d >= since]
        recent = [r for r in self._log if r["day"] >= since]
        return SignInStats(
            window_days=days,
            total=sum(d.count for d in by_day),
            unique_accounts=len({r["email"] for r in recent}),
            by_day=by_day,
            by_provider=dict(self._providers),
            last_signin=self._log[-1] if self._log else None,
        )


class RedisStore:
    """Shared store. Uses the ingest service's guarded Redis calls."""

    def __init__(self, call: Callable[[Any], Any], client_getter: Callable[[], Any]) -> None:
        self._call = call
        self._client = client_getter

    async def append(self, record: Dict[str, Any]) -> bool:
        client = self._client()
        if client is None:
            return False

        day = record["day"]
        provider = record["provider"]
        day_key = DAY_KEY.format(day=day)

        # One MULTI/EXEC: either the log entry and every counter land together, or
        # none of them do. Six separate calls left the counts and the log able to
        # disagree.
        async def _transaction():
            async with client.pipeline(transaction=True) as pipe:
                pipe.lpush(LOG_KEY, json.dumps(record))
                pipe.ltrim(LOG_KEY, 0, MAX_LOG_ENTRIES - 1)
                pipe.sadd(ACCOUNTS_KEY, record["email"])
                pipe.incr(day_key)
                pipe.expire(day_key, DAY_TTL_SECONDS)
                pipe.incr(PROVIDER_KEY.format(provider=provider))
                return await pipe.execute()

        try:
            result = await self._call(_transaction())
        except Exception as exc:  # noqa: BLE001 - a failed log must not break sign-in
            logger.warning("Sign-in log transaction failed: %s", exc)
            return False

        return result is not None

    async def stats(self, days: int) -> SignInStats:
        client = self._client()
        if client is None:
            raise RuntimeError("redis unavailable")

        today = datetime.now(timezone.utc)
        dates = [(today - timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(days - 1, -1, -1)]

        by_day: List[DayCount] = []
        for date in dates:
            value = await self._call(client.get(DAY_KEY.format(day=date)))
            by_day.append(DayCount(date=date, count=int(value or 0)))

        accounts = await self._call(client.scard(ACCOUNTS_KEY))
        providers: Dict[str, int] = {}
        for provider in ("google", "password"):
            value = await self._call(client.get(PROVIDER_KEY.format(provider=provider)))
            if value:
                providers[provider] = int(value)

        raw_last = await self._call(client.lindex(LOG_KEY, 0))
        last_signin = json.loads(raw_last) if raw_last else None

        return SignInStats(
            window_days=days,
            total=sum(day.count for day in by_day),
            unique_accounts=int(accounts or 0),
            by_day=by_day,
            by_provider=providers,
            last_signin=last_signin,
        )


def build_router(
    redis_getter: Callable[[], Any],
    redis_call: Callable[[Any], Any],
    security: Any,
    api_key_scheme: Any,
) -> APIRouter:
    """Wires the sign-in log onto the ingest app's auth and Redis plumbing."""
    router = APIRouter(prefix="/v1/signins", tags=["Sign-ins"])
    memory = MemoryStore()

    async def store() -> tuple[Store, str]:
        client = redis_getter()
        if client is not None:
            return RedisStore(redis_call, redis_getter), "redis"
        return memory, "memory"

    @router.post(
        "",
        response_model=SignInResponse,
        summary="Record a console sign-in",
        description=(
            "Appends one sign-in to the log. Never blocks the sign-in: when logging is disabled "
            "or storage is down this returns recorded=false."
        ),
    )
    async def record_signin(request: SignInRequest, x_api_key: Optional[str] = Security(api_key_scheme)):
        await security.require_auth(x_api_key, required_permission="ingest")

        if not _enabled():
            return SignInResponse(recorded=False, storage="none")

        now = datetime.now(timezone.utc)
        record = {
            "email": _normalise_email(request.email),
            "provider": request.provider,
            "role": request.role,
            "org_domain": request.org_domain,
            "at": now.isoformat(),
            "day": now.strftime("%Y-%m-%d"),
        }

        backend, kind = await store()
        try:
            recorded = await backend.append(record)
        except Exception as exc:  # noqa: BLE001 - logging must never break sign-in
            logger.warning("Sign-in log write failed: %s", exc)
            recorded = False

        logger.info("Console sign-in: %s via %s (recorded=%s)", record["email"], record["provider"], recorded)
        return SignInResponse(recorded=recorded, storage=kind if recorded else "none")

    @router.get(
        "/stats",
        response_model=SignInStats,
        summary="Sign-in counts",
        description="Totals for the console. Requires read permission; the window is in days.",
    )
    async def signin_stats(
        days: int = Query(7, ge=1, le=365, description="Window in days"),
        x_api_key: Optional[str] = Security(api_key_scheme),
    ):
        await security.require_auth(x_api_key, required_permission="read")
        backend, _ = await store()
        return await backend.stats(days)

    return router
