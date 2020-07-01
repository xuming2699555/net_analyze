# -*- coding: UTF-8 -*-
from ipAddrConverter import ipAddrConverter
import string


class rule():
    #规则的数值表示
    def __init__(self, order, ruleline):
        self.order = order
        if ruleline[-1] == '\n':
            ruleline = ruleline[0:-1]
        #处理规则字符串ruleline
        rulelist = ruleline.split()
        #print(rulelist)

        #target: accept deny dnat snat
        self.target = rulelist[0]
        print("             target:", self.target)
        self.prot = rulelist[1]
        print("             prot:", self.prot)
        self.opt = rulelist[2]
        print("             opt:", self.opt)

        #源ip和源mask的处理
        _sip = rulelist[3]
        _siplist = _sip.split('/')
        self.sip = ipAddrConverter(_siplist[0])
        print("             sip:", self.sip.to_32_bin())
        if len(_siplist) > 1:
            self.smask = int(_siplist[1])
        else:
            self.smask = 32
        print("             smask:", self.smask)

        #目的ip和目的mask的处理
        _dip = rulelist[4]
        _diplist = _dip.split('/')
        self.dip = ipAddrConverter(_diplist[0])
        print("             dip:", self.dip.to_32_bin())
        if len(_diplist) > 1:
            self.dmask = int(_diplist[1])
        else:
            self.dmask = 32
        print("             dmask:", self.dmask)

        #后面是附加说明，其中包含了端口范围。目前支持范围端口和单一值端口
        #注意端口为none表示任意端口
        self.sport = None
        self.dport = None
        for i in range(5, len(rulelist)):
            if rulelist[i].find("spt") != -1:
                spts = rulelist[i].split(':')
                self.sport = [int(spts[1]), int(spts[1])]
                if len(spts) > 2:
                    self.sport[1] = int(spts[2])
                print("             sport:", self.sport)
            if rulelist[i].find("dpt") != -1:
                dpts = rulelist[i].split(":")
                self.dport = [int(dpts[1]), int(dpts[1])]
                if len(dpts) > 2:
                    self.dport[1] = int(dpts[2])
                print("             dport:", self.dport)
            if rulelist[i].find("to") != -1:
                nataddr = rulelist[i].split(":")
                self.nat = nataddr[1]
