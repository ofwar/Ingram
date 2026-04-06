import os
import inspect
import requests
from collections import namedtuple

from loguru import logger


class POCTemplate:

    level = namedtuple('level', 'high medium low')('高', '中', '低')
    poc_classes = []

    # Class-level metadata — override in subclasses instead of repeating in __init__
    product_key = 'base'       # maps to config.product dict key
    product_version = ''
    ref = ''
    desc = ''
    vuln_level = None          # e.g. POCTemplate.level.high; None → defaults to level.low

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Capture the source file at class-definition time so __init__ can derive the name
        cls._source_file = inspect.getfile(cls)
        # Auto-register concrete POCs — skip base classes (_abstract = True) and POCTemplate itself
        if cls.product_key not in ('base', None) and not getattr(cls, '_abstract', False):
            POCTemplate.poc_classes.append(cls)

    def __init__(self, config):
        self.config = config
        self.name = self.get_file_name(self._source_file)
        self.product = config.product.get(self.product_key, self.product_key)
        self.level = (self.__class__.vuln_level
                      if self.__class__.vuln_level is not None
                      else POCTemplate.level.low)
        self.headers = {'Connection': 'close', 'User-Agent': config.user_agent}

    def get_file_name(self, file):
        return os.path.basename(file).split('.')[0]

    @staticmethod
    def register_poc(cls):
        """Deprecated — POCs are now auto-registered via __init_subclass__. No-op."""
        pass

    def verify(self, ip, port):
        pass

    def _snapshot(self, url, img_file_name, auth=None) -> int:
        """Download the image at url and save it to the snapshots directory."""
        img_path = os.path.join(self.config.out_dir, self.config.snapshots, img_file_name)
        headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}
        try:
            res = requests.get(url, auth=auth, timeout=self.config.timeout,
                               verify=False, headers=headers, stream=True)
            if res.status_code == 200 and 'head' not in res.text:
                with open(img_path, 'wb') as f:
                    for content in res.iter_content(10240):
                        f.write(content)
                return 1
        except Exception as e:
            logger.debug(e)
        return 0

    def exploit(self, results: tuple) -> int:
        return 0


class WeakPasswordPOC(POCTemplate):
    """Base class for weak / default credential checks.

    Subclasses only need to implement _check(ip, port, user, password) -> bool.
    verify() handles the users×passwords loop, exception catching, and return tuple.
    exploit() defaults to 0 — override when a snapshot can be captured.

    Example
    -------
    class MyBrandWeakPassword(WeakPasswordPOC):
        product_key = 'mybrand'

        def _check(self, ip, port, user, password):
            r = requests.get(f"http://{ip}:{port}/login",
                             auth=(user, password), timeout=self.config.timeout)
            return r.status_code == 200 and 'welcome' in r.text
    """
    _abstract = True

    def _check(self, ip, port, user, password) -> bool:
        raise NotImplementedError

    def verify(self, ip, port=80):
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    if self._check(ip, port, user, password):
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.debug(e)
        return None

    def exploit(self, results):
        return 0
