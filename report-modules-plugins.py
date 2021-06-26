#!/usr/bin/env python

import os
import sys
import logging
import pprint
import subprocess
import re
from pathlib import Path
import jinja2

from ansible.errors import AnsibleParserError
from ansible.parsing.dataloader import DataLoader
from ansible.parsing.mod_args import ModuleArgsParser
from ansible.parsing.yaml.objects import AnsibleSequence, AnsibleMapping
from ansible.template import Templar
from ansible.plugins.loader import filter_loader, lookup_loader, test_loader

if os.environ.get("LSR_DEBUG") == "true":
    logging.getLogger().setLevel(logging.DEBUG)


ROLE_DIRS = ["defaults", "examples", "files", "handlers", "library", "meta",
             "module_utils", "tasks", "templates", "tests", "vars"]

PLAY_KEYS = {
    "gather_facts",
    "handlers",
    "hosts",
    "import_playbook",
    "post_tasks",
    "pre_tasks",
    "roles",
    "tasks",
}


TASK_LIST_KWS = ["always", "block", "handlers", "post_tasks", "pre_tasks", "rescue", "tasks"]


role_modules = set()
role_ext_modules = set()
ext_modules = set()
bymodule = {}
byrole = {}
module2coll = {}
at_runtime = {"modules": {}, "roles": {}}
in_testing = {"modules": {}, "roles": {}}

def get_role_dir(role_path, dirpath):
    if role_path == dirpath:
        return None
    dir_pth = Path(dirpath)
    relpath = dir_pth.relative_to(role_path)
    base_dir = relpath.parts[0]
    if base_dir in ROLE_DIRS:
        return base_dir
    return None


def get_role_name(role_path):
    dir_pth = Path(role_path)
    if dir_pth.parts[-2] == "roles":
        return dir_pth.parts[-3] + "." + dir_pth.parts[-1]
    else:
        return dir_pth.parts[-1]


def get_file_type(item):
    if isinstance(item, AnsibleMapping):
        if "galaxy_info" in item or "dependencies" in item:
            return "meta"
        return "vars"
    elif isinstance(item, AnsibleSequence):
        return "tasks"
    else:
        raise Exception(f"Error: unknown type of file: {item}")


def get_item_type(item):
    if isinstance(item, AnsibleMapping):
        for key in PLAY_KEYS:
            if key in item:
                return "play"
        if "block" in item:
            return "block"
        return "task"
    else:
        raise Exception(f"Error: unknown type of item: {item}")


def handle_other(item, filectx):
    """handle properties of Ansible item other than vars and tasks"""
    for role in item.get("roles", []):
        print(f"\troles item role {role}")
    return


def handle_vars(item, filectx):
    """handle vars of Ansible item"""
    for var in item.get("vars", []):
        logging.debug(f"\tvar = {var}")
    return


def handle_meta(item, filectx):
    """handle meta/main.yml file"""
    for role in item.get("dependencies", []):
        print(f"\tmeta dependencies role {role}")


PLUGIN_BUILTINS = set(["lookup", "q"])


def is_builtin(plugin, filectx):
    return plugin in PLUGIN_BUILTINS


jinja2_macros = set()


def get_plugin_module(plugin, filectx):
    """find the module that defines the plugin"""
    if not plugin:
        return ''
    templar = filectx["templar"]
    if plugin in jinja2.filters.FILTERS:
        return 'jinja2.filters'
    elif plugin in jinja2.tests.TESTS:
        return 'jinja2.tests'
    elif is_builtin(plugin, filectx):
        return 'ansible.builtin'
    else:
        ctx = filter_loader.find_plugin_with_context(plugin)
        if ctx.plugin_resolved_collection:
            return ctx.plugin_resolved_collection
        ctx = test_loader.find_plugin_with_context(plugin)
        if ctx.plugin_resolved_collection:
            return ctx.plugin_resolved_collection
        ctx = lookup_loader.find_plugin_with_context(plugin)
        if ctx.plugin_resolved_collection:
            return ctx.plugin_resolved_collection
        if plugin in templar.environment.filters:
            return templar.environment.filters[plugin].__module__
        if plugin in templar.environment.tests:
            return templar.environment.tests[plugin].__module__
        elif plugin in jinja2_macros:
            return 'macro'
        else:
            print(f"Error: could not find plugin {plugin}")
            return None


def find_filters_tests(args, filectx):
    templar = filectx["templar"]
    if isinstance(args, str):
        tmpl = templar.environment.parse(source=args)
        node_types = (jinja2.nodes.Call, jinja2.nodes.Filter, jinja2.nodes.Test, jinja2.nodes.Macro)
        for item in tmpl.find_all(node_types):
            if hasattr(item, "name"):
                item_name = item.name
            elif hasattr(item.node, "name"):
                item_name = item.node.name
            else:
                print(f"\tdo not know what item is {item}")
                continue
            if isinstance(item, jinja2.nodes.Macro):
                global jinja2_macros
                jinja2_macros.add(item_name)
                print(f"\titem {item_name} {item.__class__}")
                continue
            print(f"\titem {item_name} {item.__class__} module {get_plugin_module(item_name, filectx)}")
            if item_name in ["selectattr", "rejectattr"] and len(item.args) > 1:
                print(f"\t\targ {item.args[1].value} module {get_plugin_module(item.args[1].value, filectx)}")
            if item_name in ["select", "reject"] and item.args:
                print(f"\t\targ {item.args[0].value} module {get_plugin_module(item.args[0].value, filectx)}")
            if item_name == "map" and item.args:
                print(f"\t\targ {item.args[0].value} module {get_plugin_module(item.args[0].value, filectx)}")
    elif isinstance(args, list):
        for item in args:
            find_filters_tests(item, filectx)
    elif isinstance(args, dict):
        for item in args.values():
            find_filters_tests(item, filectx)
    elif isinstance(args, (bool, int, float)):
        return
    else:
        raise Exception(f"ERROR: I don't know how to handle {args.__class__}")


def find_filters_tests_for_when_that(val, filectx):
    """when or that - val can be string or list"""
    if isinstance(val, list):
        for item in val:
            find_filters_tests_for_when_that(item, filectx)
    elif isinstance(val, (bool, int, float)):
        return
    else:
        templar = filectx["templar"]
        if templar.is_template(val):
            find_filters_tests(val, filectx)
        else:
            find_filters_tests("{{ " + val + " }}", filectx)


def handle_task(task, filectx):
    """handle a single task"""
    mod_arg_parser = ModuleArgsParser(task)
    try:
        action, args, _ = mod_arg_parser.parse(skip_action_validation=True)
    except AnsibleParserError as e:
        raise SystemExit("Couldn't parse task at %s (%s)\n%s" % (task, e.message, task))
    templar = filectx["templar"]
    if templar.is_template(args):
        print(f"\tmodule {action} has template {args}")
        find_filters_tests(args, filectx)
        # try:
        #     res = templar.template(args)
        # except AnsibleUndefinedVariable as auv:
        #     print(auv)
    elif action == "assert":
        find_filters_tests_for_when_that(args["that"], filectx)
    else:
        print(f"\tmodule {action} has no template {args}")
    if "when" in task:
        find_filters_tests_for_when_that(task["when"], filectx)
    if action == "include_role" or action == "import_role":
        print(f"\ttask role {task[action]['name']}")
    elif action in filectx["role_modules"]:
        print(f"\ttask role module {action}")
    else:
        filectx["ext_modules"].add(action)
    handle_tasks(task, filectx)


def handle_task_list(tasks, filectx):
    """item is a list of Ansible Task objects"""
    for task in tasks:
        handle_item(task, filectx)


def handle_tasks(item, filectx):
    """item has one or more fields which hold a list of Task objects"""
    for kw in TASK_LIST_KWS:
        if kw in item:
            handle_task_list(item[kw], filectx)


def handle_item(item, filectx):
    handle_other(item, filectx)
    handle_vars(item, filectx)
    item_type = get_item_type(item)
    if item_type == "task":
        handle_task(item, filectx)
    else:
        handle_tasks(item, filectx)


def parse_role(role_path):
    role_name = get_role_name(role_path)
    role_modules = set()
    library_path = Path(os.path.join(role_path, "library"))
    if library_path.is_dir():
        for mod_file in library_path.iterdir():
            if mod_file.is_file() and mod_file.stem != "__init__":
                role_modules.add(mod_file.stem)
    for (dirpath, _, filenames) in os.walk(role_path):
        role_dir = get_role_dir(role_path, dirpath)
        if not role_dir:
            continue
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            filectx = {"ext_modules": set(), "role_modules": role_modules, "templar": Templar(loader=None)}
            if role_dir == "templates":
                print(f"handle template {filepath}")
                find_filters_tests(open(filepath).read(), filectx)
                continue
            if not filepath.endswith(".yml"):
                continue
            print(f"filepath {filepath}")
            dl = DataLoader()
            ans_data = dl.load_from_file(filepath)
            if ans_data is None:
                print(f"file is empty {filepath}")
                continue
            file_type = get_file_type(ans_data)
            if file_type == "vars":
                handle_vars(ans_data, filectx)
            elif file_type == "meta":
                handle_meta(ans_data, filectx)
            else:
                for item in ans_data:
                    handle_item(item, filectx)
            for module in filectx["ext_modules"]:
                global in_testing
                global at_runtime
                fpth = Path(filepath)
                relpth = str(fpth.relative_to(Path(role_path)))
                if relpth.startswith("tests/"):
                    in_testing["modules"].setdefault(module, {}).setdefault(role_name, set()).add(relpth)
                    in_testing["roles"].setdefault(role_name, {}).setdefault(module, set()).add(relpth)
                else:
                    at_runtime["modules"].setdefault(module, {}).setdefault(role_name, set()).add(relpth)
                    at_runtime["roles"].setdefault(role_name, {}).setdefault(module, set()).add(relpth)
                global module2coll
                module2coll[module] = None

if __name__ == "__main__":
    for role_path in sys.argv[1:]:
        parse_role(role_path)
    print(f"at_runtime {pprint.pformat(at_runtime)}")
    print(f"in_testing {pprint.pformat(in_testing)}")
    venv_dir = ".venv-ansible-3"
    venv_path = Path(venv_dir)
    if not venv_path.is_dir():
        subprocess.check_call(["bash", "-c", f"""python -mvenv {venv_dir};
        . {venv_dir}/bin/activate
        pip install 'ansible==3.*'
        """])
    for module in module2coll.keys():
        argstr = f"find {venv_dir}/lib/python3.9/site-packages/ansible* -name {module}.py -print"
        res = subprocess.run(["bash", "-c", argstr], stdout=subprocess.PIPE, encoding="utf-8")
        res.check_returncode()
        for modfile in res.stdout.split("\n"):
            if modfile.endswith(f"/ansible/modules/{module}.py"):
                module2coll[module] = "ansible.builtin"
                break
            else:
                match = re.match(f"^.*/ansible_collections/([^/]+)/([^/]+)/plugins/[^/]+/{module}.py", modfile)
                if match:
                    coll = f"{match.group(1)}.{match.group(2)}"
                    module2coll[module] = coll
    print("The following modules are used at runtime:")
    builtinmods = ''
    for mod, roledict in sorted(at_runtime["modules"].items(), key=lambda item: item[0]):
        coll = module2coll[mod]
        if coll == "ansible.builtin":
            builtinmods = builtinmods + mod + ' '
            continue
        print(f"module [{mod}] in collection [{coll}] is used by these system roles: {list(roledict.keys())}")
    print(builtinmods)
    print("The following modules are used for testing:")
    builtinmods = ''
    for mod, roledict in sorted(in_testing["modules"].items(), key=lambda item: item[0]):
        coll = module2coll[mod]
        if coll == "ansible.builtin":
            builtinmods = builtinmods + mod + ' '
            continue
        print(f"module [{mod}] in collection [{coll}] is used by these system roles: {list(roledict.keys())}")
    print(builtinmods)

# elif re.match(f"/ansible/plugins/[^/]+/{module}.py", modfile):
#     module2coll[module] = "ansible.builtin"
