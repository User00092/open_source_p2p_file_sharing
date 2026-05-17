import os
import re
import requests


class ProxyUnavailableError(RuntimeError):
    """Raised when no proxy can be obtained and fail-closed policy applies."""


_VALID_PROXY_TYPES = {"http", "socks4", "socks5"}
_SAFE_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')


def _validate_env_proxy() -> dict | None:
    """
    Read PROXY_HOST/PORT/TYPE/USERNAME/PASSWORD from env.
    Returns requests-compatible proxies dict, or None if not configured.
    Raises ValueError on invalid/partial configuration.
    """
    host = os.environ.get("PROXY_HOST", "").strip()
    port_str = os.environ.get("PROXY_PORT", "").strip()
    proxy_type = os.environ.get("PROXY_TYPE", "http").strip().lower()
    username = os.environ.get("PROXY_USERNAME", "").strip()
    password = os.environ.get("PROXY_PASSWORD", "").strip()

    if not host and not port_str:
        return None

    if not host or not port_str:
        raise ValueError("PROXY_HOST and PROXY_PORT must both be set if either is configured")

    if not _SAFE_HOST_RE.match(host):
        raise ValueError("PROXY_HOST contains invalid characters")

    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError(f"PROXY_PORT must be an integer 1-65535, got: {port_str!r}")

    if proxy_type not in _VALID_PROXY_TYPES:
        raise ValueError(f"PROXY_TYPE must be one of {_VALID_PROXY_TYPES}, got: {proxy_type!r}")

    if username and password:
        auth = f"{username}:{password}@"
    elif username or password:
        raise ValueError("PROXY_USERNAME and PROXY_PASSWORD must both be set if either is provided")
    else:
        auth = ""

    proxy_url = f"{proxy_type}://{auth}{host}:{port}"
    return {"http": proxy_url, "https": proxy_url}


def _load_free_proxy() -> dict | None:
    """
    Attempt to get a free proxy from proxies.py.
    Returns requests-compatible proxies dict, or None on any failure.
    """
    try:
        from proxies import Proxies
        pool = Proxies()
        proxy = pool.get_fastest_proxy()
        if proxy is None:
            return None
        proxy_url = proxy.url
        return {"http": proxy_url, "https": proxy_url}
    except Exception:
        return None


def get_proxied_session(timeout: tuple[int, int] = (10, 30)) -> requests.Session:
    """
    Return a requests.Session configured with a proxy.

    Resolution order:
      1. PROXY_HOST/PORT env vars
      2. Free proxy from proxies.py (proxyscrape)
      3. Raises ProxyUnavailableError (fail-closed)

    Proxy credentials are never logged.
    """
    proxies_dict = None

    try:
        proxies_dict = _validate_env_proxy()
    except ValueError as exc:
        raise ProxyUnavailableError(f"Invalid proxy env configuration: {exc}") from exc

    if proxies_dict is None:
        proxies_dict = _load_free_proxy()

    if proxies_dict is None:
        raise ProxyUnavailableError(
            "No proxy available. Configure PROXY_HOST/PROXY_PORT or ensure proxyscrape is reachable."
        )

    session = requests.Session()
    session.proxies.update(proxies_dict)
    session.verify = True

    class _TimeoutAdapter(requests.adapters.HTTPAdapter):
        def send(self, *args, **kwargs):
            kwargs.setdefault("timeout", timeout)
            return super().send(*args, **kwargs)

    session.mount("http://", _TimeoutAdapter())
    session.mount("https://", _TimeoutAdapter())

    return session
