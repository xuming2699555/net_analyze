# -*- coding: UTF-8 -*-
from rule import rule
from ConflictAnalyse import ConflictAnalyse
import Interface
import trie
import util
import sys


def main(*args):
    try:
        checkid = args[0][1]
        if_use_dao = args[0][2]
    except :
        print("参数错误， 请填写 $checkid 和 $使用数据库数据（1）或者自定义和数据（0）")
        return -100, "参数错误"
    ruleset = util.GetRuleData(checkid, if_use_dao) #由filter表所有链上的规则组合而成
    natPreRuleSet, infoset = util.GetInterfaceData(checkid) #nat表的prerouting链上的规则,网口数据

    #以下是测试数据
    # rule0 = "Accept"
    # rawRule1 = "ACCEPT     tcp  --  192.168.1.1            0.0.0.0/0            tcp dpts:20000:30000\n"
    # rawRule2 = "ACCEPT     tcp  --  192.168.1.1/24            10.2.2.2            tcp dpts:22222\n"
    # rawRule3 = "ACCEPT     tcp  --  192.168.1.1/23            10.2.2.2/13            \n"
    # rawRule4 = "ACCEPT     tcp  --  192.168.1.1/20            10.168.2.2/12            tcp dpts:22:80\n"
    # rawRule5 =  "ACCEPT     tcp  --  192.168.1.1/18            10.2.2.2/11            tcp dpts:22:80\n"
    # ruleset.append(rule().rawRuleFormat(1, rawRule1))
    # ruleset.append(rule().rawRuleFormat(2, rawRule2))
    # ruleset.append(rule().rawRuleFormat(3, rawRule3))
    # ruleset.append(rule().rawRuleFormat(4, rawRule4))
    # ruleset.append(rule().rawRuleFormat(5, rawRule5))

    # rawNatRule1 = "DNAT       tcp  --  0.0.0.0/0            127.0.0.1          tcp dpt:7410 to:127.0.0.1:9200"
    # rawNatRule2 = "DNAT       tcp  --  0.0.0.0/0            10.2.2.2          tcp dpt:7410 to:10.2.2.2:9200"
    # natPreRuleSet.append(rule().rawRuleFormat(1, rawNatRule1))
    # natPreRuleSet.append(rule().rawRuleFormat(2, rawNatRule2))

    # info0 = Interface.InterfaceInfo("ens33", "10.2.2.2", "255.255.255.0")
    # info1 = Interface.InterfaceInfo("lo", "127.0.0.1", "0.0")
    # infoset.append(info0)
    # infoset.append(info1)

    #固定写法，生成针对源ip和目的ip的两颗分类树
    sttree = trie.TrieTree(0)
    dttree = trie.TrieTree(1)

    #规则集的冲突分析
    ConflictAnalyse(ruleset, sttree, dttree)
    #结果输出
    util.updateConflictAnalyseData(ruleset)

    #多网口漏洞分析
    Interface.InterfaceAnalyse(infoset, dttree, natPreRuleSet)

    #结果输出
    util.updateNICAnalyseData(infoset)


if __name__ == '__main__':
    main(sys.argv)
