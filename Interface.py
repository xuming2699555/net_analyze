# -*- coding: UTF-8 -*-
import config
from ipAddrConverter import ipAddrConverter
import trie

#多网卡漏洞检测模块


#网口信息类
class InterfaceInfo():
    def __init__(self, name, inet, netmask):
        self.name = name
        self.inet = inet
        self.binnet = ipAddrConverter(inet).to_32_bin()
        self.netmask = netmask
        self.ruleset = []
        self.dnatset = []
        self.dnatrouteset = []


#规则遗漏核查
#核查方式：在目的ip树中搜索本机有关的网口地址，获取所有目的IP等于本机网口相关IP的规则
#这里要求规则设置时直接以定单个ip地址定义，因此查询范围只有叶子节点

#DNAT导致规则无效
#核查方式：检索dnat的转发规则，如果存在针对本机ip的转发，则可能导致filter中针对本机ip的规则无效

#DNAT隐藏路径
#核查方式，检索dnat转发规则中，是否将两个都属于本机的ip作为dip进行了互相转换。存在则导致隐藏路径


def InterfaceAnalyse(infoset, dttree, natPreRuleSet):
    #infoset代表网口信息集合，dttree代表了filter规则集合，而natruleset代表了dnat规则集合

    infoset = []
    info0 = InterfaceInfo("ens33", "10.2.2.2", "255.255.255.0")
    info1 = InterfaceInfo("lo", "127.0.0.1", "0.0")
    infoset.append(info0)
    infoset.append(info1)

    #分析规则遗漏
    for info in infoset:
        for dnatrule in natPreRuleSet:
            if dnatrule.dip.ip_addr == info.inet:  #当转发规则的目的ip等于端口ip时，会造成针对该ip的filter规则无效
                info.dnatset.append(dnatrule)
                for inf in infoset:  #再次遍历网口地址，如果dnat规则的目的ip关联本机网口，而转换ip也是本机网口，则导致隐藏路径
                    if dnatrule.nat == inf.inet:
                        info.dnatrouteset.append(dnatrule)
        node = dttree.search(info.binnet, 32)
        if node == None:
            continue
        for rule in node.markrule:
            info.ruleset.append(rule)
    for info in infoset:
        print(info.name, info.dnatset, info.dnatrouteset, info.ruleset)


#遍历结束之后，每个info都关联了三个set，对应三种漏洞