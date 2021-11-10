from sarif_om import *

from src.output_parser.Parser import Parser
from src.output_parser.SarifHolder import isNotDuplicateRule, parseRule, parseResult, \
    parseArtifact, parseLogicalLocation, isNotDuplicateLogicalLocation


class Myth(Parser):
    def __init__(self):
        pass


    def parse(self, str_output):
        output = []
        current_contract = None
        lines = str_output.splitlines()
        for line in lines:
            if "====" in line:
                if current_contract is not None:
                    output.append(current_contract)
                current_contract = {
                    'errors': []
                }
                # (file, contract_name, _) = line.replace("INFO:root:contract ", '').split(':')
                # current_contract['file'] = file
                # current_contract['name'] = contract_name
                
            elif "In file:" in line:
                (file, lineno) = line.replace("In file: ", '').split(':')
                current_contract['file'] = file
                current_contract['errors'].append({'line':int(lineno)})
            elif "Contract:" in line:
                contract_name = line.replace("Contract: ",'')
                current_contract['name'] = contract_name
            
        if current_contract is not None:
            output.append(current_contract)

        print(output,"aaaaaaaaaaaaa")
        return output

    def parseSarif(self, myth_output_results, file_path_in_repo):
        resultsList = []
        logicalLocationsList = []
        rulesList = []

        for analysis in myth_output_results["analysis"]:
            for result in analysis["errors"]:
                #rule = parseRule(tool="myth", vulnerability=result["message"])
                result = parseResult(tool="myth",
                                     uri=file_path_in_repo, line=result["line"])

                resultsList.append(result)

                # if isNotDuplicateRule(rule, rulesList):
                #     rulesList.append(rule)

            # logicalLocation = parseLogicalLocation(name=analysis["name"])

            # if isNotDuplicateLogicalLocation(logicalLocation, logicalLocationsList):
            #     logicalLocationsList.append(logicalLocation)

        artifact = parseArtifact(uri=file_path_in_repo)

        tool = Tool(driver=ToolComponent(name="myth", version="myth",))

        run = Run(tool=tool, artifacts=[artifact], logical_locations=logicalLocationsList, results=resultsList)

        return run
