from dataclasses import dataclass, field
import requests
import typing


class ProxyLoadError(RuntimeError):
    """Raised when the proxy list cannot be fetched from the upstream API."""


@dataclass
class Proxy:
    ip: str
    port: int
    uptime: float
    anonymity: typing.Literal["elite", "anonymous", "transparent"]
    timeout: float
    ssl: bool = False
    url: str = field(default="")


class Proxies:
    def __init__(self):
        self._proxy_list: list[Proxy] = []
        self.load_proxies()

    def add_proxy(self, proxy: dict) -> None:
        try:
            uptime = float(proxy["uptime"])
            if uptime < 80 or not proxy.get("alive", False):
                return
            self._proxy_list.append(Proxy(
                ip=str(proxy["ip"]),
                port=int(proxy["port"]),
                anonymity=proxy["anonymity"],
                timeout=float(proxy["average_timeout"]),
                ssl=bool(proxy.get("ssl", False)),
                uptime=uptime,
                url=f"http://{proxy['ip']}:{proxy['port']}",
            ))
        except (KeyError, ValueError, TypeError):
            pass

    def load_proxies(self) -> None:
        try:
            response = requests.get(
                "https://api.proxyscrape.com/v4/free-proxy-list/get"
                "?request=display_proxies&protocol=http&proxy_format=protocolipport"
                "&format=json&anonymity=Elite,Anonymous&timeout=20000",
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
            for proxy in data.get("proxies", []):
                self.add_proxy(proxy)
        except requests.exceptions.RequestException as exc:
            raise ProxyLoadError(f"Failed to fetch proxy list: {exc}") from exc
        except Exception as exc:
            raise ProxyLoadError(f"Unexpected error loading proxies: {exc}") from exc

    def get_fastest_proxy(self) -> typing.Optional[Proxy]:
        if not self._proxy_list:
            return None
        return min(self._proxy_list, key=lambda p: p.timeout)
