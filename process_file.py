import argparse
import os
import re

re_pragma = re.compile(r"pragma solidity \^?0.[0-9].[0-9]{1,2};")
re_sol_version = re.compile(r"0.[0-9].[0-9]{1,2}")
re_import_file1 = re.compile(r"import \"[@./a-zA-z0-9-_]+.sol\";")
re_import_file2 = re.compile(r"import {[a-zA-z0-9_]+} from \"[@./a-zA-z0-9-_]+.sol\";")
dir_path_openzeppelin = os.path.abspath("@openzeppelin")
dir_path_openzeppelinV2 = os.path.abspath("@openzeppelinV2")
dir_path_openzeppelinV3 = os.path.abspath("@openzeppelinV3")
dir_path_openzeppelinV4 = os.path.abspath("@openzeppelinV4")
openzeppelin_dir_mapping = {
    "@openzeppelin/": dir_path_openzeppelin + "/",
    "@openzeppelinV2/": dir_path_openzeppelinV2 + "/",
    "@openzeppelinV3/": dir_path_openzeppelinV3 + "/",
    "@openzeppelinV4/": dir_path_openzeppelinV4 + "/",
}


class SolVersion:
    def __init__(self, first: int, second: int, third: int, allow_higher: bool):
        self.first = first
        self.second = second
        self.third = third
        self.allow_higher = allow_higher

    def compare(self, other):
        if self.first < other.first:
            return -1
        if self.first > other.first:
            return 1
        if self.second < other.second:
            return -1
        if self.second > other.second:
            return 1
        if self.third < other.third:
            return -1
        if self.third > other.third:
            return 1
        return 0


def merge(v1: SolVersion, v2: SolVersion) -> (SolVersion, bool):
    if v1.first != v2.first or v1.second != v1.second:
        return SolVersion, False
    if v1.allow_higher and v2.allow_higher:
        if v1.compare(v2) < 0:
            return v1, True
        return v2, True
    if (not v1.allow_higher) and (not v2.allow_higher):
        if v1.compare(v2) != 0:
            return SolVersion, False
        return v1, True
    if v1.allow_higher:
        if v1.compare(v2) < 0:
            return v1, True
        return SolVersion, False
    if v2.allow_higher:
        if v1.compare(v2) > 0:
            return v2, True
        return SolVersion, False
    return SolVersion, False


sol_file_mapping = {}


class SolFile:
    def __init__(self, filepath: str):
        self.filepath = filepath
        if not self._is_file_solidity():
            exit("file {} is not a solidity file".format(self.filepath))
        self.name = os.path.split(filepath)[1][:-4]

        with open(filepath) as f:
            self.file_data = f.read()
        if self._count_pragma_of_file() != 1:
            exit("file {} has {} version pragma".format(self.filepath, self._count_pragma_of_file()))
        self.sol_version = self._get_sol_version()
        self.import_files = self._get_import_files()
        self.source_code = self._get_source_code()
        print("new SolFile {}".format(self.filepath))

    #  "pragma solidity ^0.4.25" -> SolVersion(0, 4, 25, True), "pragma solidity 0.8.0" -> SolVersion(0, 8, 0, False)
    def _get_sol_version(self) -> SolVersion:
        pragma = re_pragma.findall(self.file_data)[0]
        sol_version = SolVersion(0, 0, 0, True)
        sol_version.allow_higher = ("^" in pragma)
        sol_version_string_tuple = re_sol_version.findall(pragma)[0][:len(pragma) - 1].split(".")
        sol_version.first = int(sol_version_string_tuple[0])
        sol_version.second = int(sol_version_string_tuple[1])
        sol_version.third = int(sol_version_string_tuple[2])
        return sol_version

    def _is_file_solidity(self) -> bool:
        return self.filepath.endswith(".sol") and os.path.isfile(self.filepath)

    def _count_pragma_of_file(self) -> int:
        pragmas = re_pragma.findall(self.file_data)
        return len(pragmas)

    def _get_source_code(self) -> str:
        pragmas = re_pragma.findall(self.file_data)
        source_code = self.file_data
        for pragma in pragmas:
            source_code = source_code.replace(pragma, "")
        for import_file in re_import_file1.findall(self.file_data) + re_import_file2.findall(self.file_data):
            source_code = source_code.replace(import_file, "")
        return source_code

    def _get_import_files(self) -> list:
        imports = re_import_file1.findall(self.file_data) + re_import_file2.findall(self.file_data)
        files = []
        for import_file in imports:
            self_filepath = self.filepath
            if "from" in import_file:
                filepath = os.path.abspath(
                    os.path.join(self_filepath.replace("/" + self.name + ".sol", ""), import_file.split(" ")[3][1:-2]))
            else:
                filepath = os.path.abspath(
                    os.path.join(self_filepath.replace("/" + self.name + ".sol", ""), import_file.split(" ")[1][1:-2]))
            new_sol_file = make_sol_file(filepath)
            merge_sol_version, ok = merge(self.sol_version, new_sol_file.sol_version)
            if not ok:
                exit("solidity version conflict between {} and {}".format(self.filepath, new_sol_file.filepath))
            self.sol_version, new_sol_file.sol_version = merge_sol_version, merge_sol_version
            files.append(new_sol_file)
        return files

    def output(self) -> str:
        if len(self.import_files) == 0:
            return self.source_code
        filepath_in_order = []
        visited_files = {}
        for file_path in sol_file_mapping.keys():
            visited_files[file_path] = 0
        valid = True

        def dfs(s: str):
            nonlocal valid
            visited_files[s] = 1
            for sol_file in sol_file_mapping[s].import_files:
                if visited_files[sol_file.filepath] == 0:
                    dfs(sol_file.filepath)
                    if not valid:
                        return
                elif visited_files[sol_file.filepath] == 1:
                    valid = False
                    return
            visited_files[s] = 2
            filepath_in_order.append(s)

        for filepath in sol_file_mapping.keys():
            if valid and not visited_files[filepath]:
                dfs(filepath)

        if not valid:
            exit("circular import")

        text = ""
        for filepath in filepath_in_order:
            text += sol_file_mapping[filepath].source_code
        return text

    def save(self, target_filepath: str):
        while os.path.exists(target_filepath):
            target_filepath = target_filepath[:-4]+"(1)"+target_filepath[-4:]

        with open(target_filepath, "w+") as f:
            f.write("pragma solidity {}{}.{}.{};\n".format("^" if self.sol_version.allow_higher else "",
                                                           self.sol_version.first,
                                                           self.sol_version.second,
                                                           self.sol_version.third) + self.output())
        print("[+]output file {}".format(target_filepath))


def make_sol_file(filepath: str) -> SolFile:
    for k, v in openzeppelin_dir_mapping.items():
        if k in filepath:
            index = filepath.find(k)
            filepath = filepath[index:].replace(k, v)
            break
    if filepath in sol_file_mapping:
        return sol_file_mapping[filepath]
    new_sol_file = SolFile(filepath)
    sol_file_mapping[filepath] = new_sol_file
    return new_sol_file


def format_sol_file(filepath: str, target_filepath: str):
    make_sol_file(filepath).save(target_filepath)


# 找到根文件, main file
def find_main_files(mapping: dict[str:SolFile], only_contract: bool) -> list[str]:
    res_main_files = []
    not_main_files = set()
    for filepath, sol_file in mapping.items():
        not_main_files.update([import_file.filepath for import_file in sol_file.import_files])
    for filepath, sol_file in mapping.items():
        if ((not only_contract) or ("contract" in sol_file.source_code)) and (filepath not in not_main_files):
            res_main_files.append(filepath)
    return res_main_files


if __name__ == '__main__':
    print("[+]Info: Processing file start")

    parser = argparse.ArgumentParser(description='Preprocess the contract source code to obtain information ('
                                                 'solidity)')
    parser.add_argument('path', metavar='PATH', type=str, help='directory or main file')
    parser.add_argument('--output_dir', '-o', type=str, help='merged file output directory', required=True)
    parser.add_argument('--only_contract', '-oc', action="store_true", help='only output main file with contract')
    args = parser.parse_args()
    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)
    if not os.path.isdir(args.output_dir):
        exit("output_dir exists and is not a directory")
    if not os.path.exists(args.path):
        exit("path {} do not exists".format(args.path))
    if os.path.isdir(args.path):
        solidity_files = []
        for i, j, k in os.walk(args.path):
            for m in k:
                if m.endswith(".sol"):
                    solidity_files.append(os.path.join(i, m))
        for solidity_file in solidity_files:
            make_sol_file(solidity_file)
        main_files = find_main_files(sol_file_mapping, args.only_contract)
        if len(main_files) == 1:
            print("[+]main file: {}".format(main_files[0]))
            format_sol_file(main_files[0], args.path)
            exit(0)
        if len(main_files) > 1:
            print("[+]main files: {}".format(main_files))
            for main_file in main_files:
                format_sol_file(main_file, args.output_dir+"/o_"+sol_file_mapping[main_file].name+".sol")
            exit(0)
        exit("no main file")
    elif args.path.endswith(".sol"):
        format_sol_file(args.path, args.output_dir+"/o_"+os.path.split(args.path)[1])
        exit(0)
    exit("path {} is not a dir or a sol file".format(args.path))

