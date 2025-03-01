#!/usr/bin/env python3

import docker
import json
import os
import re
import sys
import tarfile
import yaml
import tempfile
from shutil import copyfile, rmtree

from solidity_parser import parser

from src.output_parser.Conkas import Conkas
from src.output_parser.HoneyBadger import HoneyBadger
from src.output_parser.Maian import Maian
from src.output_parser.Manticore import Manticore
from src.output_parser.Mythril import Mythril
from src.output_parser.Osiris import Osiris
from src.output_parser.Oyente import Oyente
from src.output_parser.Securify import Securify
from src.output_parser.Slither import Slither
from src.output_parser.Smartcheck import Smartcheck
from src.output_parser.Solhint import Solhint
from src.output_parser.Mythril2 import Mythril2
from src.output_parser.Slither2 import Slither2
from src.output_parser.Manticore2 import Manticore2
from src.output_parser.Securify2 import Securify2
from time import time


client = docker.from_env()

"""
get solidity compiler version
"""
def get_solc_version(file, logs):
    try:
        with open(file, 'r', encoding='utf-8') as fd:
            sourceUnit = parser.parse(fd.read())
            solc_version = sourceUnit['children'][0]['value']
            solc_version = solc_version.strip('^')
            solc_version = solc_version.split('.')
            return (int(solc_version[1]), int(solc_version[2]))
    except:
        print('\x1b[1;33m' + 'WARNING: could not parse solidity file to get solc version' + '\x1b[0m')
        logs.write('WARNING: could not parse solidity file to get solc version \n')
    return (None, None)


"""
pull images
"""
def pull_image(image, logs):
    try:
        print('pulling ' + image + ' image, this may take a while...')
        logs.write('pulling ' + image + ' image, this may take a while...\n')
        image = client.images.pull(image)
        print('image pulled')
        logs.write('image pulled\n')

    except docker.errors.APIError as err:
        print(err)
        logs.write(err + '\n')


"""
mount volumes
"""
def mount_volumes(dir_path, logs):
    try:
        volume_bindings = {os.path.abspath(dir_path): {'bind': '/data', 'mode': 'rw'}}
        return volume_bindings
    except os.error as err:
        print(err)
        logs.write(err + '\n')


"""
stop container
"""
def stop_container(container, logs):
    try:
        if container is not None:
            container.stop(timeout=0)
    except (docker.errors.APIError) as err:
        print(err)
        logs.write(str(err) + '\n')


"""
remove container
"""
def remove_container(container, logs):
    try:
        if container is not None:
            container.remove()
    except (docker.errors.APIError) as err:
        print(err)
        logs.write(err + '\n')


"""
write output
"""
def parse_results(output, tool, file_name, container, cfg, logs, results_folder, start, end, sarif_outputs,
                  file_path_in_repo, output_version):
    output_folder = os.path.join(results_folder, file_name)

    results = {
        'contract': file_name,
        'tool': tool,
        'start': start,
        'end': end,
        'duration': end - start,
        'analysis': None
    }
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    with open(os.path.join(output_folder, 'result.log'), 'w', encoding='utf-8') as f:
        f.write(output)

    if 'output_in_files' in cfg:
        try:
            with open(os.path.join(output_folder, 'result.tar'), 'wb') as f:
                output_in_file = cfg['output_in_files']['folder']
                bits, stat = container.get_archive(output_in_file)
                for chunk in bits:
                    f.write(chunk)
        except Exception as e:
            print(output)
            print(e)
            print('\x1b[1;31m' + 'ERROR: could not get file from container. file not analysed.' + '\x1b[0m')
            logs.write('ERROR: could not get file from container. file not analysed.\n')

    try:
        sarif_holder = sarif_outputs[file_name]
        if tool == 'oyente':
            results['analysis'] = Oyente().parse(output)
            # Sarif Conversion
            sarif_holder.addRun(Oyente().parseSarif(results, file_path_in_repo))
        elif tool == 'osiris':
            results['analysis'] = Osiris().parse(output)
            sarif_holder.addRun(Osiris().parseSarif(results, file_path_in_repo))
        elif tool == 'honeybadger':
            results['analysis'] = HoneyBadger().parse(output)
            sarif_holder.addRun(HoneyBadger().parseSarif(results, file_path_in_repo))
        elif tool == 'smartcheck':
            results['analysis'] = Smartcheck().parse(output)
            sarif_holder.addRun(Smartcheck().parseSarif(results, file_path_in_repo))
        elif tool == 'solhint':
            results['analysis'] = Solhint().parse(output)
            sarif_holder.addRun(Solhint().parseSarif(results, file_path_in_repo))
        elif tool == 'maian':
            results['analysis'] = Maian().parse(output)
            sarif_holder.addRun(Maian().parseSarif(results, file_path_in_repo))
        elif tool == 'mythril':
            results['analysis'] = json.loads(output)
            sarif_holder.addRun(Mythril().parseSarif(results, file_path_in_repo))
        elif tool == 'mythril2':
            results['analysis'] = json.loads(output)
            sarif_holder.addRun(Mythril2().parseSarif(results,file_path_in_repo))
        elif tool == 'securify':
            if len(output) > 0 and output[0] == '{':
                results['analysis'] = json.loads(output)
            elif os.path.exists(os.path.join(output_folder, 'result.tar')):
                tar = tarfile.open(os.path.join(output_folder, 'result.tar'))
                try:
                    output_file = tar.extractfile('results/results.json')
                    results['analysis'] = json.loads(output_file.read())
                    sarif_holder.addRun(Securify().parseSarif(results, file_path_in_repo))
                except Exception as e:
                    print('pas terrible')
                    output_file = tar.extractfile('results/live.json')
                    results['analysis'] = {
                        file_name: {
                            'results': json.loads(output_file.read())["patternResults"]
                        }
                    }
                    sarif_holder.addRun(Securify().parseSarifFromLiveJson(results, file_path_in_repo))
        elif tool == 'securify2':
            if len(output) > 0 and output[0] == '{':
                results['analysis'] = json.loads(output)
            elif os.path.exists(os.path.join(output_folder, 'result.tar')):
                tar = tarfile.open(os.path.join(output_folder, 'result.tar'))
                try:
                    output_file = tar.extractfile('results/results.json')
                    results['analysis'] = json.loads(output_file.read())
                    sarif_holder.addRun(Securify2().parseSarif(results, file_path_in_repo))
                except Exception as e:
                    print('pas terrible')
                    output_file = tar.extractfile('results/live.json')
                    results['analysis'] = {
                        file_name: {
                            'results': json.loads(output_file.read())["patternResults"]
                        }
                    }
                    sarif_holder.addRun(Securify2().parseSarifFromLiveJson(results, file_path_in_repo))
        elif tool == 'slither':
            if os.path.exists(os.path.join(output_folder, 'result.tar')):
                tar = tarfile.open(os.path.join(output_folder, 'result.tar'))
                output_file = tar.extractfile('output.json')
                results['analysis'] = json.loads(output_file.read())
                sarif_holder.addRun(Slither().parseSarif(results, file_path_in_repo))
        elif tool == 'slither2':
            if os.path.exists(os.path.join(output_folder, 'result.tar')):
                tar = tarfile.open(os.path.join(output_folder, 'result.tar'))
                output_file = tar.extractfile('output.json')
                results['analysis'] = json.loads(output_file.read())
                sarif_holder.addRun(Slither2().parseSarif(results, file_path_in_repo))
        elif tool == 'manticore':
            if os.path.exists(os.path.join(output_folder, 'result.tar')):
                tar = tarfile.open(os.path.join(output_folder, 'result.tar'))
                m = re.findall('Results in /(mcore_.+)', output)
                results['analysis'] = []
                for fout in m:
                    output_file = tar.extractfile('results/' + fout + '/global.findings')
                    results['analysis'].append(Manticore().parse(output_file.read().decode('utf8')))
                sarif_holder.addRun(Manticore().parseSarif(results, file_path_in_repo))
        elif tool == 'manticore2':
            if os.path.exists(os.path.join(output_folder, 'result.tar')):
                tar = tarfile.open(os.path.join(output_folder, 'result.tar'))
                m = re.findall('Results in /(mcore_.+)', output)
                results['analysis'] = []
                for fout in m:
                    output_file = tar.extractfile('results/' + fout + '/global.findings')
                    results['analysis'].append(Manticore2().parse(output_file.read().decode('utf8')))
                sarif_holder.addRun(Manticore2().parseSarif(results, file_path_in_repo))
        elif tool == 'conkas':
            results['analysis'] = Conkas().parse(output)
            sarif_holder.addRun(Conkas().parseSarif(results, file_path_in_repo))

        sarif_outputs[file_name] = sarif_holder

    except Exception as e:
        # ignore
        pass

    if output_version == 'v1' or output_version == 'all':
        with open(os.path.join(output_folder, 'result.json'), 'w') as f:
            json.dump(results, f, indent=2)

    if output_version == 'v2' or output_version == 'all':
        with open(os.path.join(output_folder, 'result.sarif'), 'w') as sarifFile:
            json.dump(sarif_outputs[file_name].printToolRun(tool=tool), sarifFile, indent=2)



"""
analyse solidity files
"""
def analyse_files(tool, file, logs, now, sarif_outputs, output_version, import_path):
    try:
        cfg_path = os.path.abspath('config/tools/' + tool + '.yaml')
        with open(cfg_path, 'r', encoding='utf-8') as ymlfile:
            try:
                cfg = yaml.safe_load(ymlfile)
            except yaml.YAMLError as exc:
                print(exc)
                logs.write(exc)

        # create result folder with time
        results_folder = 'results/' + tool + '/' + now
        if not os.path.exists(results_folder):
            os.makedirs(results_folder)
        # os.makedirs(os.path.dirname(results_folder), exist_ok=True)

        # check if config file as all required fields
        if 'default' not in cfg['docker_image'] or cfg['docker_image'] == None:
            logs.write(tool + ': default docker image not provided. please check you config file.\n')
            sys.exit(tool + ': default docker image not provided. please check you config file.')
        elif 'cmd' not in cfg or cfg['cmd'] == None:
            logs.write(tool + ': commands not provided. please check you config file.\n')
            sys.exit(tool + ': commands not provided. please check you config file.')

        if import_path == "FILE":
            import_path = file
            file_path_in_repo = file
        else:
            file_path_in_repo = file.replace(import_path, '')  # file path relative to project's root directory

        file_name = os.path.basename(file)
        file_name = os.path.splitext(file_name)[0]

        working_dir = tempfile.mkdtemp()
        copyfile(file, os.path.join(working_dir, os.path.basename(file)))
        file = os.path.join(working_dir, os.path.basename(file))

        # bind directory path instead of file path to allow imports in the same directory
        volume_bindings = mount_volumes(working_dir, logs)

        start = time()

        (solc_version, solc_version_minor) = get_solc_version(file, logs)

        if isinstance(solc_version, int) and solc_version < 5 and 'solc<5' in cfg['docker_image']:
            image = cfg['docker_image']['solc<5']
        # if there's no version or version >5, choose default
        else:
            image = cfg['docker_image']['default']

        if not client.images.list(image):
            pull_image(image, logs)

        cmd = cfg['cmd']
        if '{contract}' in cmd:
            cmd = cmd.replace('{contract}', '/data/' + os.path.basename(file))
        else:
            cmd += ' /data/' + os.path.basename(file)

        if '{version}' in cmd:
            with open(file) as f:
                file_data = f.read()
                pattern = re.compile(r'pragma solidity (>=)?(.?[0-9]+)+', re.I)
                a=pattern.search(file_data)
                b=str(a.group())
                c=re.search(r'([0-9]+.?)+',b)
                c=c.group()
                cmd = cmd.replace('{version}' ,c)
        
        print(cmd)
        container = None
        img = ["trailofbits/eth-security-toolbox","mythril/myth","securify"]
        try:
            if image in img:
                container = client.containers.run(image,
                                              cmd,
                                              detach=True,
                                              # cpu_quota=150000,
                                              volumes=volume_bindings,
                                              entrypoint="")
            else:                                  
                container = client.containers.run(image,
                                                cmd,
                                                detach=True,
                                                # cpu_quota=150000,
                                                volumes=volume_bindings
                                                )
            try:
                container.wait(timeout=(30 * 60))
            except Exception as e:
                pass
            output = container.logs().decode('utf8').strip()
            if (output.count('Solc experienced a fatal error') >= 1 or output.count('compilation failed') >= 1):
                print(
                    '\x1b[1;31m' + 'ERROR: Solc experienced a fatal error. Check the results file for more info' + '\x1b[0m')
                logs.write('ERROR: Solc experienced a fatal error. Check the results file for more info\n')

            end = time()

            parse_results(output, tool, file_name, container, cfg, logs, results_folder, start, end, sarif_outputs,
                          file_path_in_repo, output_version)
        finally:
            stop_container(container, logs)
            remove_container(container, logs)
            rmtree(working_dir)

    except (docker.errors.APIError, docker.errors.ContainerError, docker.errors.ImageNotFound) as err:
        print(err)
        logs.write(err + '\n')
