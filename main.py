import argparse
import json
import os
import time
from jsonpath import jsonpath

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

    def add_issue(self, position: str, issue_list: list[Issue]):
        self.issues[position] = issue_list

    def save(self):
        f = open(self.output_filepath, "w")
        f.write(self.to_json())
        f.close()

    def to_json(self) -> str:
        return json.dumps(self.issues, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4, ensure_ascii=False)


STRATEGY = 0  # 当有超过多少tools报出漏洞即认为可信
TOOLS = ["conkas", "mythril", "osiris", "slither", "oyente", "solhint", "smartcheck", "honeybadger", "manticore",
         "maian", "securify"]

ISSUE_UNKNOWN = Issue(-1, "未知")
ISSUE_OTHER = Issue(0, "其他")
ISSUE_ARITHMETIC = Issue(1, "整数溢出")
ISSUE_ACCESS_CONTROL = Issue(2, "访问控制")
ISSUE_REENTRANCY = Issue(3, "重入")
ISSUE_TIME_MANIPULATION = (4, "时间操纵")
ISSUE_UNCHECKED_CALLS = Issue(5, "未检查的call")
ISSUE_TRANSACTION_ORDER_DEPENDENCE = Issue(6, "交易顺序依赖")
ISSUE_DOS = Issue(7, "拒绝服务")
ISSUE_RANDOM = Issue(8, "弱随机数")

ISSUE_LIST = [ISSUE_OTHER, ISSUE_ARITHMETIC, ISSUE_ACCESS_CONTROL, ISSUE_REENTRANCY, ISSUE_TIME_MANIPULATION, ISSUE_UNCHECKED_CALLS, ISSUE_TRANSACTION_ORDER_DEPENDENCE, ISSUE_DOS, ISSUE_RANDOM]

VULNERABILITY_MAPPING = {
    "is_lock_vulnerable": ISSUE_OTHER,
    "is_prodigal_vulnerable": ISSUE_ACCESS_CONTROL,
    "is_suicidal_vulnerable": ISSUE_ACCESS_CONTROL,
    "Delegatecall to user controlled address": ISSUE_ACCESS_CONTROL,
    "Delegatecall to user controlled function": ISSUE_ACCESS_CONTROL,
    "INVALID instruction": ISSUE_OTHER,
    "Potential reentrancy vulnerability": ISSUE_REENTRANCY,
    "Potentially reading uninitialized memory at instruction": ISSUE_OTHER,
    "Potentially reading uninitialized storage": ISSUE_OTHER,
    "Reachable ether leak to sender": ISSUE_ACCESS_CONTROL,
    "Reachable ether leak to sender via argument": ISSUE_ACCESS_CONTROL,
    "Reachable external call to sender": ISSUE_ACCESS_CONTROL,
    "Reachable external call to sender via argument": ISSUE_ACCESS_CONTROL,
    "Reachable SELFDESTRUCT": ISSUE_ACCESS_CONTROL,
    "Reentrancy multi-million ether bug": ISSUE_REENTRANCY,
    "Returned value at CALL instruction is not used": ISSUE_UNCHECKED_CALLS,
    "Unsigned integer overflow at ADD instruction": ISSUE_ARITHMETIC,
    "Unsigned integer overflow at MUL instruction": ISSUE_ARITHMETIC,
    "Unsigned integer overflow at SUB instruction": ISSUE_ARITHMETIC,
    "Warning BLOCKHASH instruction used": ISSUE_OTHER,
    "Warning NUMBER instruction used": ISSUE_OTHER,
    "Warning ORIGIN instruction used": ISSUE_ACCESS_CONTROL,
    "Warning TIMESTAMP instruction used": ISSUE_TIME_MANIPULATION,
    "Call data forwarded with delegatecall()": ISSUE_ACCESS_CONTROL,
    "DELEGATECALL to a user-supplied address": ISSUE_ACCESS_CONTROL,
    "Dependence on predictable environment variable": ISSUE_OTHER,
    "Dependence on predictable variable": ISSUE_OTHER,
    "Ether send": ISSUE_ACCESS_CONTROL,
    "Exception state": ISSUE_OTHER,
    "Integer Overflow": ISSUE_ARITHMETIC,
    "Integer Overflow ": ISSUE_ARITHMETIC,
    "Integer Underflow": ISSUE_ARITHMETIC,
    "Integer Underflow ": ISSUE_ARITHMETIC,
    "Message call to external contract": ISSUE_REENTRANCY,
    "Multiple Calls": ISSUE_OTHER,
    "State change after external call": ISSUE_REENTRANCY,
    "Transaction order dependence": ISSUE_TRANSACTION_ORDER_DEPENDENCE,
    "Unchecked CALL return value": ISSUE_UNCHECKED_CALLS,
    "Unchecked SUICIDE": ISSUE_ACCESS_CONTROL,
    "Use of tx.origin": ISSUE_ACCESS_CONTROL,
    "callstack_bug": ISSUE_DOS,
    "concurrency_bug": ISSUE_OTHER,
    "division_bugs": ISSUE_ARITHMETIC,
    "overflow_bugs": ISSUE_ARITHMETIC,
    "reentrancy_bug": ISSUE_REENTRANCY,
    "signedness_bugs": ISSUE_ARITHMETIC,
    "time_dependency_bug": ISSUE_TIME_MANIPULATION,
    "truncation_bugs": ISSUE_ARITHMETIC,
    "underflow_bugs": ISSUE_ARITHMETIC,
    "Callstack Depth Attack Vulnerability.": ISSUE_DOS,
    "Integer Overflow.": ISSUE_ARITHMETIC,
    "Integer Underflow.": ISSUE_ARITHMETIC,
    "Parity Multisig Bug 2.": ISSUE_ACCESS_CONTROL,
    "Re-Entrancy Vulnerability.": ISSUE_REENTRANCY,
    "Timestamp Dependency.": ISSUE_TIME_MANIPULATION,
    "DAO": ISSUE_REENTRANCY,
    "DAOConstantGas": ISSUE_REENTRANCY,
    "LockedEther": ISSUE_OTHER,
    "MissingInputValidation": ISSUE_OTHER,
    "RepeatedCall": ISSUE_OTHER,
    "TODAmount": ISSUE_TRANSACTION_ORDER_DEPENDENCE,
    "TODReceiver": ISSUE_TRANSACTION_ORDER_DEPENDENCE,
    "TODTransfer": ISSUE_TRANSACTION_ORDER_DEPENDENCE,
    "UnhandledException": ISSUE_UNCHECKED_CALLS,
    "UnrestrictedEtherFlow": ISSUE_ACCESS_CONTROL,
    "UnrestrictedWrite": ISSUE_ACCESS_CONTROL,
    "arbitrary-send": ISSUE_ACCESS_CONTROL,
    "assembly": ISSUE_OTHER,
    "calls-loop": ISSUE_DOS,
    "constable-states": ISSUE_OTHER,
    "constant-function": ISSUE_OTHER,
    "controlled-delegatecall": ISSUE_ACCESS_CONTROL,
    "deprecated-standards": ISSUE_OTHER,
    "erc20-indexed": ISSUE_OTHER,
    "erc20-interface": ISSUE_OTHER,
    "external-function": ISSUE_OTHER,
    "incorrect-equality": ISSUE_OTHER,
    "locked-ether": ISSUE_OTHER,
    "low-level-calls": ISSUE_UNCHECKED_CALLS,
    "naming-convention": ISSUE_OTHER,
    "reentrancy-benign": ISSUE_REENTRANCY,
    "reentrancy-eth": ISSUE_REENTRANCY,
    "reentrancy-no-eth": ISSUE_REENTRANCY,
    "shadowing-abstract": ISSUE_OTHER,
    "shadowing-builtin": ISSUE_OTHER,
    "shadowing-local": ISSUE_OTHER,
    "shadowing-state": ISSUE_OTHER,
    "solc-version": ISSUE_OTHER,
    "suicidal": ISSUE_ACCESS_CONTROL,
    "timestamp": ISSUE_TIME_MANIPULATION,
    "tx-origin": ISSUE_ACCESS_CONTROL,
    "uninitialized-local": ISSUE_OTHER,
    "uninitialized-state": ISSUE_OTHER,
    "uninitialized-storage": ISSUE_OTHER,
    "unused-return": ISSUE_UNCHECKED_CALLS,
    "unused-state": ISSUE_OTHER,
    "SOLIDITY_ADDRESS_HARDCODED": ISSUE_OTHER,
    "SOLIDITY_ARRAY_LENGTH_MANIPULATION": ISSUE_ARITHMETIC,
    "SOLIDITY_BALANCE_EQUALITY": ISSUE_OTHER,
    "SOLIDITY_BYTE_ARRAY_INSTEAD_BYTES": ISSUE_OTHER,
    "SOLIDITY_CALL_WITHOUT_DATA": ISSUE_REENTRANCY,
    "SOLIDITY_DEPRECATED_CONSTRUCTIONS": ISSUE_OTHER,
    "SOLIDITY_DIV_MUL": ISSUE_ARITHMETIC,
    "SOLIDITY_ERC20_APPROVE": ISSUE_OTHER,
    "SOLIDITY_ERC20_FUNCTIONS_ALWAYS_RETURN_FALSE": ISSUE_OTHER,
    "SOLIDITY_ERC20_TRANSFER_SHOULD_THROW": ISSUE_OTHER,
    "SOLIDITY_EXACT_TIME": ISSUE_TIME_MANIPULATION,
    "SOLIDITY_EXTRA_GAS_IN_LOOPS": ISSUE_OTHER,
    "SOLIDITY_FUNCTIONS_RETURNS_TYPE_AND_NO_RETURN": ISSUE_OTHER,
    "SOLIDITY_GAS_LIMIT_IN_LOOPS": ISSUE_DOS,
    "SOLIDITY_INCORRECT_BLOCKHASH": ISSUE_OTHER,
    "SOLIDITY_LOCKED_MONEY": ISSUE_OTHER,
    "SOLIDITY_MSGVALUE_EQUALS_ZERO": ISSUE_OTHER,
    "SOLIDITY_OVERPOWERED_ROLE": ISSUE_OTHER,
    "SOLIDITY_PRAGMAS_VERSION": ISSUE_OTHER,
    "SOLIDITY_PRIVATE_MODIFIER_DONT_HIDE_DATA": ISSUE_OTHER,
    "SOLIDITY_REDUNDANT_FALLBACK_REJECT": ISSUE_OTHER,
    "SOLIDITY_REVERT_REQUIRE": ISSUE_OTHER,
    "SOLIDITY_SAFEMATH": ISSUE_OTHER,
    "SOLIDITY_SEND": ISSUE_UNCHECKED_CALLS,
    "SOLIDITY_SHOULD_NOT_BE_PURE": ISSUE_OTHER,
    "SOLIDITY_SHOULD_NOT_BE_VIEW": ISSUE_OTHER,
    "SOLIDITY_SHOULD_RETURN_STRUCT": ISSUE_OTHER,
    "SOLIDITY_TRANSFER_IN_LOOP": ISSUE_DOS,
    "SOLIDITY_TX_ORIGIN": ISSUE_ACCESS_CONTROL,
    "SOLIDITY_UINT_CANT_BE_NEGATIVE": ISSUE_ARITHMETIC,
    "SOLIDITY_UNCHECKED_CALL": ISSUE_UNCHECKED_CALLS,
    "SOLIDITY_UPGRADE_TO_050": ISSUE_OTHER,
    "SOLIDITY_USING_INLINE_ASSEMBLY": ISSUE_OTHER,
    "SOLIDITY_VAR": ISSUE_ARITHMETIC,
    "SOLIDITY_VAR_IN_LOOP_FOR": ISSUE_ARITHMETIC,
    "SOLIDITY_VISIBILITY": ISSUE_OTHER,
    "SOLIDITY_WRONG_SIGNATURE": ISSUE_OTHER,
    "indent": ISSUE_OTHER,
    "max-line-length": ISSUE_OTHER,
    "hidden_state_update": ISSUE_OTHER,
    "uninitialised_struct": ISSUE_OTHER,
    "inheritance_disorder": ISSUE_OTHER,
    "straw_man_contract": ISSUE_REENTRANCY,
    "hidden_transfer": ISSUE_OTHER,
    "balance_disorder": ISSUE_OTHER,
    "type_overflow": ISSUE_ARITHMETIC,
    "Integer_Overflow": ISSUE_ARITHMETIC,
    "Integer_Underflow": ISSUE_ARITHMETIC,
    "Reentrancy": ISSUE_REENTRANCY,
    "Time Manipulation": ISSUE_TIME_MANIPULATION,
    "Transaction Ordering Dependence": ISSUE_TRANSACTION_ORDER_DEPENDENCE,
    "Unchecked Low Level Call": ISSUE_UNCHECKED_CALLS,
}
TOOL_VULNERABILITY_RANGE = {
    "conkas": [ISSUE_ARITHMETIC, ISSUE_REENTRANCY, ISSUE_TIME_MANIPULATION, ISSUE_TRANSACTION_ORDER_DEPENDENCE,
               ISSUE_UNCHECKED_CALLS],
    "mythril": [ISSUE_ARITHMETIC, ISSUE_ACCESS_CONTROL, ISSUE_REENTRANCY, ISSUE_UNCHECKED_CALLS,
                ISSUE_TIME_MANIPULATION],
    "osiris": [ISSUE_DOS, ISSUE_ARITHMETIC, ISSUE_REENTRANCY, ISSUE_TIME_MANIPULATION, ],
    "slither": [ISSUE_ACCESS_CONTROL, ISSUE_DOS, ISSUE_ACCESS_CONTROL, ISSUE_UNCHECKED_CALLS, ISSUE_REENTRANCY,
                ISSUE_TIME_MANIPULATION],
    "oyente": [ISSUE_DOS, ISSUE_ARITHMETIC, ISSUE_ACCESS_CONTROL, ISSUE_REENTRANCY, ISSUE_TIME_MANIPULATION],
    "solhint": [],
    "smartcheck": [ISSUE_ARITHMETIC, ISSUE_REENTRANCY, ISSUE_TIME_MANIPULATION, ISSUE_DOS, ISSUE_UNCHECKED_CALLS,
                   ISSUE_ACCESS_CONTROL],
    "honeybadger": [ISSUE_REENTRANCY, ISSUE_ARITHMETIC],
    "manticore": [ISSUE_ARITHMETIC, ISSUE_ACCESS_CONTROL, ISSUE_REENTRANCY, ISSUE_UNCHECKED_CALLS,
                  ISSUE_TIME_MANIPULATION],
    "maian": [ISSUE_ACCESS_CONTROL],
    "securify": [ISSUE_REENTRANCY, ISSUE_TRANSACTION_ORDER_DEPENDENCE, ISSUE_UNCHECKED_CALLS, ISSUE_ACCESS_CONTROL]
}


class Contract:
    def __init__(self, name: str, language: str, filepath: str):
        self.name = name  # 名称
        self.language = language  # 语言种类
        self.filepath = filepath  # 源代码路径

    def analyze(self, time_limit: int = 60, ) -> AnalysisResult:
        result = {}
        time_now = time.time()
        if not os.path.isdir("aggregated_result"):
            if os.path.exists("aggregated_result"):
                print("[-]Error: Result dir `aggregated_result` is not empty")
                exit()
            os.mkdir("aggregated_result")
        analysis_result = AnalysisResult(
            "aggregated_result/" + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(time_now)) + "_" + self.name)
        tool_start_time = {}  # dict[tool: start time]
        for i in TOOLS:
            time_now = time.time()
            tool_start_time[i] = time_now
            smartBugs.exec_cmd(create_parser_with_args(["-t", i, "-f", self.filepath]))
        for i in TOOLS:
            time_now_format_list = [time.strftime("%Y%m%d_%H%M", time.localtime(tool_start_time[i] + 60)),
                                    time.strftime("%Y%m%d_%H%M", time.localtime(tool_start_time[i]))]  # 时间可能有误差
            flag = False
            result_json_filepath = ""
            for time_now_format in time_now_format_list:
                result_json_filepath = "results/{0}/{1}/{2}/result.json".format(i, time_now_format, self.name)
                if os.path.exists(result_json_filepath):
                    flag = True
                    break
            if not flag:
                print("[-]Error: tool {0} exec result not found, result filepath {1}".format(i, time_now_format_list))
                continue
            result_i, ok = phase_result_json(result_json_filepath, i)
            if not ok:
                print(
                    "[-]Error: tool {0} exec result cannot phase, result filepath {1}".format(i, result_json_filepath))
                continue
            result[i] = result_i
        for position, issue_list in aggregate(result).items():
            analysis_result.add_issue(position, issue_list)
        analysis_result.save()
        return analysis_result


# 聚合结果
def aggregate(result: dict[str:dict[int:Issue]]) -> dict[int:list[Issue]]:
    aggregate_result = {}
    statistical_result = {}
    confidence_count = {}
    for issue_type in ISSUE_LIST:
        confidence_count[issue_type] = 0
    for tool in result.keys():
        for issue_type in TOOL_VULNERABILITY_RANGE[tool]:
            confidence_count[issue_type] += 1
    for tool, tool_res in result.items():
        for line, issue_list in tool_res.items():
            for issue in issue_list:
                if line not in statistical_result:
                    statistical_result[line] = {}
                if issue not in statistical_result[line]:
                    statistical_result[line][issue] = 0
                statistical_result[line][issue] += 1
    for line, issue_count in statistical_result.items():
        for issue, count in issue_count.items():
            if count >= STRATEGY*confidence_count[issue]:
                if line not in aggregate_result:
                    aggregate_result[line] = []
                aggregate_result[line].append(issue)
    print(statistical_result)
    return aggregate_result


def phase_result_json(filepath: str, tool: str) -> (dict[int:list[Issue]], bool):
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
        return {}, False


def phase_result_json_conkas(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    if ("analysis" not in data) or (not data["analysis"]):
        f.close()
        return result, False
    for i in data['analysis']:
        line = int(i['line_number'])
        issue = VULNERABILITY_MAPPING[i['vuln_type']]
        if line not in result:
            result[line] = []
        result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_mythril(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    issues = jsonpath(data, "$..issues")
    for i in issues:
        for iss in i:
            line = iss['lineno']
            issue = VULNERABILITY_MAPPING[iss['title']]
            if line not in result:
                result[line] = []
            result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_osiris(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    issues = jsonpath(data, "$..errors")
    for i in issues:
        for iss in i:
            line = iss['line']
            issue = VULNERABILITY_MAPPING[iss['message']]
            if line not in result:
                result[line] = []
            result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_slither(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    for i in data['analysis']:
        title = i['check']
        lines = jsonpath(i['elements'], "$..lines")
        for li in lines:
            for line in li:
                issue = VULNERABILITY_MAPPING[title]
                if line not in result:
                    result[line] = []
                result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_oyente(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    issues = jsonpath(data, "$..errors")
    for i in issues:
        for iss in i:
            line = iss['line']
            issue = VULNERABILITY_MAPPING[iss['message']]
            if line not in result:
                result[line] = []
            result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_solhint(filepath: str) -> (dict[int:list[Issue]], bool):
    # TODO
    f = open(filepath)
    data = json.load(f)
    result = {}
    if "analysis" not in data:
        f.close()
        return result, False
    for i in data['analysis']:
        line = i['line']
        issue = VULNERABILITY_MAPPING[i['message']]
        if line not in result:
            result[line] = []
        result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_smartcheck(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    if "analysis" not in data:
        f.close()
        return result, False
    for i in data["analysis"]:
        line = i["line"]
        issue = VULNERABILITY_MAPPING[i["name"]]
        if line not in result:
            result[line] = []
        result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_honeybadger(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    if ("analysis" not in data) or (len(data["analysis"]) == 0) or ("errors" not in data["analysis"][0]):
        f.close()
        return result, False
    for error in data["analysis"][0]["errors"]:
        line = error["line"]
        issue = VULNERABILITY_MAPPING[error["message"]]
        if line not in result:
            result[line] = []
        result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_manticore(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    if "analysis" not in data or (len(data["analysis"]) == 0):
        f.close()
        return result, False
    for i in data["analysis"][0]:
        line = i["line"]
        issue = VULNERABILITY_MAPPING[i["name"]]
        if line not in result:
            result[line] = []
        result[line].append(issue)
    f.close()
    return result, True


def phase_result_json_maian(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    if "analysis" not in data:
        f.close()
        return result, False
    for k, v in data["analysis"].items():
        if v:
            line = 0
            if line not in result:
                result[line] = []
            result[line].append(VULNERABILITY_MAPPING[k])
    f.close()
    return result, True


def phase_result_json_securify(filepath: str) -> (dict[int:list[Issue]], bool):
    f = open(filepath)
    data = json.load(f)
    result = {}
    if ("analysis" not in data) or (len(data["analysis"]) == 0) or (
            "results" not in list(data["analysis"].values())[0]):
        f.close()
        return result, False
    for k, v in list(data["analysis"].values())[0]["results"].items():
        for line in v["violations"]:
            if line not in result:
                result[line] = []
            result[line].append(VULNERABILITY_MAPPING[k])
    f.close()
    return result, True


if __name__ == '__main__':
    print("[+]Analyzing start")
    contract = Contract("integer_overflow_add", "solidity",
                        "/Users/xiaoyao/PycharmProjects/smartbugs/dataset/arithmetic/integer_overflow_add.sol")
    res = contract.analyze()
    print("[+]Save result in {} successfully!".format(res.output_filepath))
