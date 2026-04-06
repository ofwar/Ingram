import requests

from .base import WeakPasswordPOC


class NuuoWeakPassword(WeakPasswordPOC):
    product_key = 'nuuo'

    def _check(self, ip, port, user, password):
        data = {'language': 'en', 'user': user, 'pass': password, 'submit': 'Login'}
        r = requests.post(f"http://{ip}:{port}/login.php", data=data,
                          headers=self.headers, timeout=self.config.timeout, verify=False)
        return r.status_code == 200 and 'loginfail' not in r.text
