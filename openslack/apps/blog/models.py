# -*- coding: utf-8 -*-
from utils.rpc import ZeroRPClient
from django.conf import settings

class Blog:

    def __init__(self):
        self.client=ZeroRPClient()

    def get(self, id):
        return self.client.qa_get(id)

    def save(self):
        self.client.qa_save("title", "content", "wechat", "submit_time", async=True)
        if self.client == "success":
            return True
        else:
            return False

    def list(self, page=1, num=100):
        self.client.qa_list(page,num)
        if self.client == "success":
            return True
        else:
            return False

    def filter(self, params={}):
        self.client.qa_filter(params, async=True)
        if self.client == "success":
            return True
        else:
            return False
