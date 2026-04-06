import requests

from .base import WeakPasswordPOC


class InstarWeakPassword(WeakPasswordPOC):
    product_key = 'instar'

    def _check(self, ip, port, user, password):
        r = requests.get(f"http://{ip}:{port}/login.cgi",
                         auth=(user, password), headers=self.headers,
                         timeout=self.config.timeout, verify=False)
        return r.status_code == 200
