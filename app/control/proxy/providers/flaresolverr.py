"""FlareSolverr-backed managed clearance provider."""

import asyncio
import json
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse

from app.platform.logging.logger import logger
from app.platform.config.snapshot import get_config
from app.platform.runtime.ids import next_hex
from ..models import ClearanceBundle, ClearanceMode


def _extract_all_cookies(cookies: list[dict]) -> str:
    return "; ".join(f"{c.get('name')}={c.get('value')}" for c in cookies)


def _split_proxy_auth(proxy_url: str) -> tuple[str, str, str]:
    """Return a FlareSolverr proxy URL plus optional username/password fields."""
    parsed = urlparse(proxy_url)
    if not parsed.username and not parsed.password:
        return proxy_url, "", ""

    hostname = parsed.hostname or ""
    netloc = hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    clean_url = urlunparse(
        (
            parsed.scheme,
            netloc,
            parsed.path or "",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    return clean_url, parsed.username or "", parsed.password or ""


# Grok2API → FlareSolverr must not use HTTP_PROXY / ALL_PROXY / system proxies:
# tunnels to localhost often get CONNECT 403 from the same egress proxies used for Grok.
_FS_DIRECT_OPENER = urllib_request.build_opener(urllib_request.ProxyHandler({}))


class FlareSolverrClearanceProvider:
    """Refresh CF clearance bundles via a FlareSolverr instance."""

    async def refresh_bundle(
        self,
        *,
        affinity_key: str,
        proxy_url:    str,
        target_url:   str = "https://grok.com",
    ) -> ClearanceBundle | None:
        cfg = get_config()
        mode = ClearanceMode.parse(cfg.get_str("proxy.clearance.mode", "none"))
        if mode != ClearanceMode.FLARESOLVERR:
            return None
        fs_url      = cfg.get_str("proxy.clearance.flaresolverr_url", "")
        timeout_sec = cfg.get_int("proxy.clearance.timeout_sec", 60)
        if not fs_url:
            return None

        use_egress = cfg.get_bool("proxy.clearance.flaresolverr_use_egress_proxy", True)
        retry_direct = cfg.get_bool(
            "proxy.clearance.flaresolverr_retry_direct_when_no_cookies",
            False,
        )

        result = await self._solve(
            fs_url       = fs_url,
            proxy_url    = proxy_url,
            timeout_sec  = timeout_sec,
            target_url   = target_url,
            use_egress   = use_egress,
            retry_direct = retry_direct,
        )
        if not result:
            logger.warning(
                "flaresolverr clearance refresh failed: affinity={} proxy={} target={}",
                affinity_key, proxy_url or "<direct>", target_url,
            )
            return None
        host = result.get("clearance_host", "grok.com")

        return ClearanceBundle(
            bundle_id    = f"flaresolverr:{affinity_key}@{host}",
            cf_cookies   = result.get("cookies", ""),
            user_agent   = result.get("user_agent", ""),
            affinity_key = affinity_key,
            clearance_host = host,
        )

    async def _solve(
        self,
        *,
        fs_url:       str,
        proxy_url:    str,
        timeout_sec:  int,
        target_url:   str,
        use_egress:   bool,
        retry_direct: bool,
    ) -> dict[str, str] | None:
        target = target_url.strip() or "https://grok.com"

        attempts: list[str | None] = []
        trimmed = (proxy_url or "").strip()
        if use_egress and trimmed:
            attempts.append(trimmed)
        if not attempts:
            attempts.append(None)
        elif retry_direct and use_egress and trimmed:
            attempts.append(None)

        for idx, eff_proxy in enumerate(attempts):
            if idx > 0 and eff_proxy is None:
                logger.warning(
                    "flaresolverr retrying without egress proxy "
                    "(clearance IP may not match proxy egress; disable if CF rejects tokens)"
                )

            parsed = await self._solve_once(
                fs_url      = fs_url,
                proxy_url   = eff_proxy,
                timeout_sec = timeout_sec,
                target      = target,
            )
            if parsed:
                return parsed

        return None

    async def _solve_once(
        self,
        *,
        fs_url:      str,
        proxy_url:   str | None,
        timeout_sec: int,
        target:      str,
    ) -> dict[str, str] | None:
        session = ""
        try:
            if proxy_url:
                clean_proxy_url, username, password = _split_proxy_auth(proxy_url)
                if username or password:
                    session = f"grok2api-{next_hex()}"
                    create_payload: dict = {
                        "cmd": "sessions.create",
                        "session": session,
                        "proxy": {"url": clean_proxy_url},
                    }
                    if username:
                        create_payload["proxy"]["username"] = username
                    if password:
                        create_payload["proxy"]["password"] = password
                    created = await self._post_flaresolverr(
                        fs_url=fs_url,
                        payload=create_payload,
                        timeout_sec=timeout_sec,
                    )
                    if created.get("status") != "ok":
                        logger.warning(
                            "flaresolverr session create failed: status={} message={}",
                            created.get("status"), created.get("message", ""),
                        )
                        return None

            payload: dict = {
                "cmd":        "request.get",
                "url":        target,
                "maxTimeout": timeout_sec * 1000,
            }
            if session:
                payload["session"] = session
            elif proxy_url:
                payload["proxy"] = {"url": proxy_url}

            result = await self._post_flaresolverr(
                fs_url=fs_url,
                payload=payload,
                timeout_sec=timeout_sec,
            )
            if result.get("status") != "ok":
                logger.warning(
                    "flaresolverr returned non-ok status: status={} message={}",
                    result.get("status"), result.get("message", ""),
                )
                return None

            solution = result.get("solution", {})
            cookies  = solution.get("cookies", [])
            if not cookies:
                logger.warning(
                    "flaresolverr returned no cookies "
                    "(FS often logs 'Challenge not detected' when the target URL never shows "
                    "a Cloudflare page; cookies stay empty until a challenge actually runs)"
                )
                return None

            ua = solution.get("userAgent", "") or ""
            host = (urlparse(target).hostname or "").lower()
            filtered = [
                cookie for cookie in cookies
                if not host or not cookie.get("domain") or host.endswith(str(cookie.get("domain", "")).lstrip(".").lower())
            ]
            chosen = filtered or cookies
            return {
                "cookies":    _extract_all_cookies(chosen),
                "user_agent": ua,
                "clearance_host": host or "grok.com",
            }

        except HTTPError as exc:
            body_text = exc.read().decode("utf-8", "replace")[:300]
            logger.warning("flaresolverr http request failed: status={} body={}", exc.code, body_text)
        except URLError as exc:
            logger.warning("flaresolverr connection failed: reason={}", exc.reason)
        except Exception as exc:
            logger.warning("flaresolverr request failed: error={}", exc)
        finally:
            if session:
                await self._destroy_session(
                    fs_url=fs_url,
                    session=session,
                    timeout_sec=timeout_sec,
                )

        return None

    async def _post_flaresolverr(
        self,
        *,
        fs_url: str,
        payload: dict,
        timeout_sec: int,
    ) -> dict:
        body = json.dumps(payload).encode()
        request = urllib_request.Request(
            f"{fs_url.rstrip('/')}/v1",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )

        def _post() -> dict:
            with _FS_DIRECT_OPENER.open(request, timeout=timeout_sec + 30) as resp:
                return json.loads(resp.read().decode())

        return await asyncio.to_thread(_post)

    async def _destroy_session(
        self,
        *,
        fs_url: str,
        session: str,
        timeout_sec: int,
    ) -> None:
        try:
            await self._post_flaresolverr(
                fs_url=fs_url,
                payload={"cmd": "sessions.destroy", "session": session},
                timeout_sec=timeout_sec,
            )
        except Exception as exc:
            logger.warning(
                "flaresolverr session destroy failed: session={} error={}",
                session,
                exc,
            )


__all__ = ["FlareSolverrClearanceProvider"]
