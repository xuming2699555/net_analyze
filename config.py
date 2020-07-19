# -*- coding: UTF-8 -*-
import json

class config():
    def __init__(self):
        f = open("config.json", mode="r")
        text = f.read()
        f.close()
        paras = json.loads(text)
        self.host = paras["host"]
        self.username = paras["username"]
        self.password = paras["password"]
        self.database = paras["database"]
        self.table_name = paras["table_name"]
        self.rulePath = ""
        self.natPath = ""
        self.ifCheckRule = True
        self.ifCheckNat = True


configs = config()
