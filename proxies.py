from dataclasses import dataclass
import requests
import typing


@dataclass
class Proxy:
    ip: str
    port: int
    uptime: float
    anonymity: typing.Literal["elite", "anonymous", "transparent"]
    timeout: float
    ssl: bool = False
    url: str = None


class Proxies:
    def __init__(self):
        self._proxy_list: typing.List[Proxy] = list()
        self.load_proxies()

    def add_proxy(self, proxy: dict):
        anonymity = proxy["anonymity"]
        timeout = float(proxy["average_timeout"])
        ssl = bool(proxy["ssl"])
        uptime = float(proxy["uptime"])
        ip = proxy["ip"]
        port = int(proxy["port"])

        if uptime >= 80 and proxy["alive"]:
            self._proxy_list.append(Proxy(ip=ip, port=port, anonymity=anonymity, timeout=timeout, ssl=ssl, uptime=uptime,
                                          url=f"http://{ip}:{port}"))

    def load_proxies(self):
        response = requests.get("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=protocolipport&format=json&anonymity=Elite,Anonymous&timeout=20000")
        if response.status_code != 200:
            raise requests.exceptions.RequestException(f"Received response code {response.status_code}")

        complete_data = response.json()

        for proxy in complete_data["proxies"]:
            self.add_proxy(proxy)

    def get_fastest_proxy(self) -> Proxy:
        return min(self._proxy_list, key=lambda proxy: proxy.timeout)
