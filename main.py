import argparse
import json
import os
import time

import smartBugs

from src.interface.cli import create_parser_with_args


class Issue:
    def __init__(self, issue_type: int, name: str):
        self.issue_type = issue_type
        self.name = name


class AnalysisResult:
    def __init__(self, output_filepath: str):
        if os.path.exists(output_filepath):
            print("[-]Error: Output filepath is not empty")
            print("[-]Exit...")
            exit()
        self.output_filepath = output_filepath
        self.issues = {}

    def add_issue(self, position: str, issue: Issue):
        self.issues[position] = issue

    def save(self):
        f = open(self.output_filepath, "w")
        f.write(json.dumps(self.issues, indent=4))
        f.close()


STRATEGY = 0.5  # 当有超过多少tools报出漏洞即认为可信
# TOOLS = ["conkas", "mythril", "osiris", "slither", "oyente", "solhint", "smartcheck", "honeybadger", "manticore",
#          "maian", "securify"]
TOOLS = ["honeybadger"]
# TODO 合并漏洞类型
ISSUE_UNKNOWN = Issue(0, "未知")
ISSUE_INTEGER_OVERFLOW = Issue(1, "整数上溢")


class Contract:
    def __init__(self, name: str, language: str, filepath: str):
        self.name = name  # 名称
        self.language = language  # 语言种类
        self.filepath = filepath  # 源代码路径

    def analyze(self, time_limit: int = 60, ) -> AnalysisResult:
        result = []
        time_now = time.time()
        if not os.path.isdir("aggregated_result"):
            if os.path.exists("aggregated_result"):
                print("[-]Error: Result dir `aggregated_result` is not empty")
                exit()
            os.mkdir("aggregated_result")
        analysis_result = AnalysisResult(
            "aggregated_result/" + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(time_now)) + "_" + self.name)
        for i in TOOLS:
            time_now = time.time()
            time_now_format_list = [time.strftime("%Y%m%d_%H%M", time.localtime(time_now + 60)),
                                    time.strftime("%Y%m%d_%H%M", time.localtime(time_now))]  # 时间可能有误差
            smartBugs.exec_cmd(create_parser_with_args(["-t", i, "-f", self.filepath]))
            flag = False
            print(time_now_format_list)
            for time_now_format in time_now_format_list:
                result_json_filepath = "results/{0}/{1}/{2}/result.json".format(i, time_now_format, self.name)
                print(result_json_filepath)
                if os.path.exists(result_json_filepath):
                    flag = True
                    break
            if not flag:
                print("[-]Error: tool {0} exec result not found".format(i))
                continue
            result.append(phase_result_json(result_json_filepath, i))
        for position, issue in aggregate(result).items():
            analysis_result.add_issue(position, issue)
        analysis_result.save()
        return analysis_result


# 聚合结果
def aggregate(result: list[dict[str:Issue]]) -> dict[str:Issue]:
    # TODO
    return {}


def phase_result_json(filepath: str, tool: str) -> dict[str:Issue]:
    if tool == "conkas":
        return phase_result_json_conkas(filepath)
    elif tool == "mythril":
        return phase_result_json_mythril(filepath)
    elif tool == "osiris":
        return phase_result_json_osiris(filepath)
    elif tool == "slither":
        return phase_result_json_slither(filepath)
    elif tool == "oyente":
        return phase_result_json_oyente(filepath)
    elif tool == "solhint":
        return phase_result_json_solhint(filepath)
    elif tool == "smartcheck":
        return phase_result_json_smartcheck(filepath)
    elif tool == "honeybadger":
        return phase_result_json_honeybadger(filepath)
    elif tool == "manticore":
        return phase_result_json_manticore(filepath)
    elif tool == "maian":
        return phase_result_json_maian(filepath)
    elif tool == "securify":
        return phase_result_json_securify(filepath)
    else:
        print("[-]ERROR: Unknown tool", tool)
        return {}


def phase_result_json_conkas(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_mythril(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_osiris(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_slither(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_oyente(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_solhint(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_smartcheck(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_honeybadger(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_manticore(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_maian(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


def phase_result_json_securify(filepath: str) -> dict[str:Issue]:
    # TODO
    f = open(filepath)
    data = json.load(f)
    res = {}
    for i in data[""]:
        pos = ""
        issue = ISSUE_UNKNOWN
        res[pos] = ISSUE_UNKNOWN
    f.close()
    return res


if __name__ == '__main__':
    # TODO
    print("[+]Analyzing start")
    contract = Contract("arbitrary_location_write_simple", "solidity", "/Users/xiaoyao/PycharmProjects/smartbugs/dataset/access_control/arbitrary_location_write_simple.sol")
    res = contract.analyze()
    print(res)
