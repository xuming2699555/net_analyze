import MysqlInterface

def updateConflictAnalyseData(ruleset):
    # 此函数用于规则冲突分析结果据上传
    f = open("output/ruleAnalyse_output.txt", mode="w+")
    print("防火墙规则冲突分析结果")
    f.write("防火墙规则冲突分析结果\n")
    for r in ruleset:
        if len(r.cset) > 0:
            print("-----------------------------------------")
            f.write("-----------------------------------------\n")
            print("被检测规则：", r.order, "\n与之冲突的规则：", r.cset)
            f.write("被检测规则：{}\n与之冲突的规则：{}\n".format(r.order, r.cset))
    f.close()


def updateNICAnalyseData(data):
    # 此函数用于多网口漏洞分析结果数据上传
    f = open("output/interface_output.txt", mode="w+")
    print("多网卡漏洞冲突检测结果")
    f.write("多网卡漏洞冲突检测结果\n")
    for info in data:
        print("-----------------------------------------")
        f.write("-----------------------------------------\n")
        print("网口名称：", info.name, "\n可能导致filter规则无效的dnat规则：", info.dnatset,
              "\n可能导致隐藏路径访问本机的dnat规则：", info.dnatrouteset, "\n针对本机网口的filter规则：", info.ruleset)
        f.write("网口名称：{}\n可能导致filter规则无效的dnat规则：{}\n可能导致隐藏路径访问本机的dnat规则：{}\n针对本机网口的filter规则：{}\n".format(
            info.name, info.dnatset, info.dnatrouteset, info.ruleset))
    f.close()

#获取防火墙filter规则数据
def GetRuleData(checkid, if_use_dao):
    if if_use_dao == 1: #从数据库中读取数据
        print("读取数据库数据……")

    else: #直接读取参数数据
        pass

    return []

#获取多网卡分析数据
def GetInterfaceData(checkid):
    return [], []