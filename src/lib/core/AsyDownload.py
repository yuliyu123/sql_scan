#!/usr/bin/env python
# -*- coding:utf-8 -*-

import aiohttp
import asyncio


class AsyDownloader(object):
    async def async_get(self, url):  # 通过async def定义的函数是原生的协程对象
        # print("get: %s" % url)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as r:
                if r.status != 200:
                    return None
                text = await r.text()
                return text

    # def get(self, url):
    #     r = requests.get(url, timeout=10)
    #     if r.status_code != 200:
    #         return None
    #     _str = r.text
    #     return _str
    #
    # def post(self, url, data):
    #     r = requests.post(url, data)
    #     _str = r.text
    #     return _str

    async def asy_download(self, url, htmls):
        if url is None:
            return None
        _str = {}
        _str["url"] = url
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as r:
            # r = requests.get(url, timeout=10)
                    if r.status_code != 200:
                        return None
                    _str["html"] = r.text
        except Exception as e:
            return None
        htmls.append(_str)

