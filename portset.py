import portion


class portset(object):
    def __init__(self):
        super().__init__()
        self.count = 0
        self.spset = {}
        self.dpset = {}

    def insert(self, rule):
        self.count += 1
        order = rule.order
        #sport处理
        if rule.sport == None:
            self.spset[order] = portion.closed(0, 65335)
        else:
            self.spset[order] = portion.closed(rule.sport[0], rule.sport[1])

        #dport处理
        if rule.dport == None:
            self.dpset[order] = portion.closed(0, 65335)
        else:
            self.dpset[order] = portion.closed(rule.dport[0], rule.dport[1])

    #为了简化计算，当端口设置为any时，端口段为None，冲突检查函数返回None表示返回全集，返回空列表表示无冲突
    def check(self, rule):
        if self.count == 0:
            return set()
        else:
            if rule.sport == None and rule.dport == None:
                return None

            #sport conflict set
            spcset = set()

            if rule.sport != None:
                spp = portion.closed(rule.sport[0], rule.sport[1])
                for key in self.spset.keys():
                    if spp.overlaps(self.spset[key]):
                        spcset.add(key)
                if rule.dport == None:
                    return spcset

            #dport conflict set
            dpcset = set()

            if rule.dport != None:
                dpp = portion.closed(rule.dport[0], rule.dport[1])
                for key in self.dpset.keys():
                    if dpp.overlaps(self.dpset[key]):
                        dpcset.add(key)
                if rule.sport == None:
                    return dpcset

            #都不是any
            fcset = set(spcset).intersection(set(dpcset))
            return fcset
