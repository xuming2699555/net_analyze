# -*- coding: UTF-8 -*-
import portset

# 冲突分析主函数，输入：规则集、待插入节点的源IP的分类树、currule->Rule目的IP的分类树
# 输出： 将在规则集中每个规则对象添加cset属性，代表与该规则发生冲突的规则集合
def ConflictAnalyse(ruleset, sttree, dttree):
    if len(ruleset) == 0:
        return -1
    # 规则集第一条规则为默认规则
    global_rule = ruleset[0]

    # trie树分别处理两个ip域
    # 初始化端口冲突检测
    pset = portset.portset()
    for rule in ruleset:
        rule.stnode = sttree.insert(rule)
        rule.dtnode = dttree.insert(rule)
        pset.insert(rule)

    # 冲突分析
    for rule in ruleset:
        # 构造sip元组的冲突集
        sipcset = set()
        sipConflictUnderSet = set()
        sipConflictUpperSet = set()
        for r in rule.stnode.passrule:
            sipcset.add(r.order)
            sipConflictUnderSet.add(r.order)
        for r in rule.stnode.markrule:
            sipcset.add(r.order)
            sipConflictUnderSet.add(r.order)
            sipConflictUpperSet.add(r.order)  # 本节点的冲突规则同时属于两类冲突集
        # 遍历父节点，获取被包含的冲突集
        tempPtr = rule.stnode
        while tempPtr.preNode != None:
            tempPtr = tempPtr.preNode
            for r in tempPtr.markrule:
                sipcset.add(r.order)
                sipConflictUpperSet.add(r.order)

        # 构造dip元组的冲突集
        dipcset = set()
        dipConflictUnderSet = set()
        dipConflictUpperSet = set()
        for r in rule.dtnode.passrule:
            dipcset.add(r.order)
            dipConflictUnderSet.add(r.order)
        for r in rule.dtnode.markrule:
            dipcset.add(r.order)
            dipConflictUnderSet.add(r.order)
            dipConflictUpperSet.add(r.order)  # 本节点的冲突规则同时属于两类冲突集
        # 遍历父节点，获取被包含的冲突集
        tempPtr = rule.dtnode
        while tempPtr.preNode != None:
            tempPtr = tempPtr.preNode
            for r in tempPtr.markrule:
                dipcset.add(r.order)
                dipConflictUpperSet.add(r.order)

        # 构造两个端口元组的冲突集
        portcset = pset.check(rule)

        # 求交集
        cset = sipcset.intersection(dipcset)
        #
        if portcset != None:
            cset = cset.intersection(set(portcset))

        # 移除自身
        cset.remove(rule.order)
        rule.cset = cset
