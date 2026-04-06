import requests

from .base import WeakPasswordPOC


class DvrWeakPassword(WeakPasswordPOC):
    product_key = 'dvr'

    def _check(self, ip, port, user, password):
        url = (f'http://{ip}:{port}/cgi-bin/gw.cgi?xml=<juan ver="" squ="" dir="0">'
               f'<rpermission usr="{user}" pwd="{password}"><config base=""/>'
               f'<playback base=""/></rpermission></juan>')
        r = requests.get(url, headers=self.headers, timeout=self.config.timeout, verify=False)
        if r.status_code == 200 and '<rpermission' in r.text:
            items = r.text.split()
            idx = items.index('<rpermission')
            return '0' in items[idx + 1]
        return False
