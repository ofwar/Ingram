"""根据指纹给出目标产品信息"""
import hashlib
import re
import requests

from loguru import logger
from lxml import etree


def _parse(req, rule_val, html_cache):
    """判断 requests 返回值是否符合指纹规则
    rule_val 可能是多种规则的且关系: xxx&&xxx...
    html_cache: dict keyed on id(req), avoids re-parsing the same response.
    """
    def check_one(item):
        left, right = re.search(r'(.*)=`(.*)`', item).groups()

        if left == 'md5':
            if hashlib.md5(req.content).hexdigest() == right:
                return True
        elif left == 'title':
            html = html_cache.setdefault(id(req), etree.HTML(req.text))
            titles = html.xpath('//title')
            if titles and right.lower() in titles[0].xpath('string(.)').lower():
                return True
        elif left == 'body':
            html = html_cache.setdefault(id(req), etree.HTML(req.text))
            for node in html.xpath('//body')[0]:
                if right.lower() in node.xpath('string(.)').lower():
                    return True
        elif left == 'headers':
            for header_item in req.headers.items():
                if right.lower() in ''.join(header_item).lower():
                    return True
        elif left == 'status_code':
            return int(req.status_code) == int(right)
        return False

    return all(map(check_one, rule_val.split('&&')))


def fingerprint(ip, port, config):
    req_dict = {}   # cache HTTP responses by path
    html_cache = {} # cache parsed HTML trees by id(response object)
    session = requests.session()
    headers = {'Connection': 'close', 'User-Agent': config.user_agent}
    for rule in config.rules:
        try:
            req = req_dict.get(rule.path) or session.get(f"http://{ip}:{port}{rule.path}", headers=headers, timeout=config.timeout)
            if (rule.path not in req_dict) and (req.status_code == 200):
                req_dict[rule.path] = req
            if _parse(req, rule.val, html_cache):
                return rule.product
        except Exception as e:
            logger.debug(e)
    return None