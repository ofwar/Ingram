import base64
import requests

from .base import WeakPasswordPOC


class AVTechWeakPassword(WeakPasswordPOC):
    product_key = 'avtech'

    def _check(self, ip, port, user, password):
        account = base64.b64encode(f"{user}:{password}".encode('utf8')).decode()
        r = requests.get(f"http://{ip}:{port}/cgi-bin/nobody/VerifyCode.cgi?account={account}",
                         headers=self.headers, timeout=self.config.timeout, verify=False)
        # split('\n')[1] may raise IndexError on malformed responses — caught by WeakPasswordPOC.verify
        return r.status_code == 200 and r.text.split('\n')[1] == 'OK'
