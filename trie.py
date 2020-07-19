# -*- coding: UTF-8 -*-
from rule import rule
from ipAddrConverter import ipAddrConverter


class TrieNode():
    #二元树节点类
    def __init__(self, rule=None):
        #值域
        self.rule = rule
        self.passrule = []
        self.markrule = []
        #子树
        self.left = None
        self.right = None
        #用于回溯节点
        self.preNode = None


class TrieTree():
    #二元树类
    #type代表二元树所对应的元组，分为源ip和目的ip，0或者1
    def __init__(self, type):
        self.root = TrieNode()
        self.type = type
        self.nodecount = 1

    def insert(self, rule):
        #向二元树中添加一个规则计数，trie树的节点插入操作就是规则计数操作
        if self.type == 0:
            #将ip地址转换成二进制按位存储的数组
            addr = rule.sip.to_32_bin()
            mask = rule.smask
        else:
            addr = rule.dip.to_32_bin()
            mask = rule.dmask

        ptr = self.root
        temp = 0
        while temp < mask:
            ptr.passrule.append(rule)
            if addr[temp] == "0":
                if ptr.left == None:
                    ptr.left = TrieNode()
                    ptr.left.preNode = ptr #新建节点的父节点
                    self.nodecount += 1
                ptr = ptr.left
            else:
                if ptr.right == None:
                    #新建节点
                    ptr.right = TrieNode()
                    ptr.right.preNode = ptr #新建节点的父节点
                    self.nodecount += 1
                ptr = ptr.right
            temp += 1
        ptr.markrule.append(rule)
        return ptr

    def search(self, ip, mask):
        temp = 0
        p = self.root
        while temp < mask and p != None:
            if ip[temp] == "0":
                p = p.left
            if ip[temp] == "1":
                p = p.right
            temp += 1
        return p
