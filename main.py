# -*- coding: UTF-8 -*-
from rule import rule
from ConflictAnalyse import ConflictAnalyse
import Interface
import trie
import util


def main():
    ruleset = []
    filterRuleSet = []  #由filter表所有链上的规则组合而成
    natPreRuleSet = []  # nat表的prerouting链上的规则
    #TODO规则数据集获取

    #以下是测试数据
    rule0 = "Accept"
    rule1 = rule(
        1,
        "ACCEPT     tcp  --  192.168.1.1            0.0.0.0/0            tcp dpts:20000:30000\n"
    )
    ruleset.append(rule1)
    rule2 = rule(
        2,
        "ACCEPT     tcp  --  192.168.1.1/24            10.2.2.2            tcp dpts:22222\n"
    )
    ruleset.append(rule2)
    ruleset.append(
        rule(
            3,
            "ACCEPT     tcp  --  192.168.1.1/23            10.2.2.2/13            \n"
        ))
    ruleset.append(
        rule(
            4,
            "ACCEPT     tcp  --  192.168.1.1/20            10.2.2.2/12            tcp dpts:22:80\n"
        ))
    ruleset.append(
        rule(
            5,
            "ACCEPT     tcp  --  192.168.1.1/18            10.2.2.2/11            tcp dpts:22:80\n"
        ))
    natPreRuleSet.append(
        rule(
            1,
            "DNAT       tcp  --  0.0.0.0/0            127.0.0.1          tcp dpt:7410 to:127.0.0.1:9200"
        ))
    natPreRuleSet.append(
        rule(
            2,
            "DNAT       tcp  --  0.0.0.0/0            10.2.2.2          tcp dpt:7410 to:10.2.2.2:9200"
        ))

    #固定写法，生成针对源ip和目的ip的两颗分类树
    sttree = trie.TrieTree(0)
    dttree = trie.TrieTree(1)

    #规则集的冲突分析
    ConflictAnalyse(ruleset, sttree, dttree)
    for r in ruleset:
        if len(r.cset) > 0:
            #结果输出
            util.updateConflictAnalyseData(r.order, r.cset)
        #print(len(r.cset))

    #测试数据
    infoset = []
    info0 = Interface.InterfaceInfo("ens33", "10.2.2.2", "255.255.255.0")
    info1 = Interface.InterfaceInfo("lo", "127.0.0.1", "0.0")
    infoset.append(info0)
    infoset.append(info1)

    #多网口漏洞分析
    Interface.InterfaceAnalyse(infoset, dttree, natPreRuleSet)

    #结果输出
    util.updateNICAnalyseData(infoset)


if __name__ == '__main__':
    main()
