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
from ansible.plugins.loader import filter_loader, lookup_loader, module_loader, test_loader

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
    if "when" in item:
        filectx["plugins"].extend(find_plugins_for_when_that(item["when"], filectx))


def __do_handle_vars(vars, filectx):
    templar = filectx["templar"]
    if vars is None or not vars:
        return
    elif isinstance(vars, (int, bool, float)):
        return
    elif isinstance(vars, list):
        for item in vars:
            __do_handle_vars(item, filectx)
    elif isinstance(vars, dict):
        for item in vars.values():
            __do_handle_vars(item, filectx)
    elif templar.is_template(vars):
        filectx["plugins"].extend(find_plugins(vars, filectx))


def handle_vars(item, filectx):
    """handle vars of Ansible item"""
    __do_handle_vars(item.get("vars"), filectx)


def handle_meta(item, filectx):
    """handle meta/main.yml file"""
    pass


PLUGIN_BUILTINS = set(["lookup", "q"])


def is_builtin(plugin, filectx):
    return plugin in PLUGIN_BUILTINS


jinja2_macros = set()


class PluginItem(object):
    def __init__(self, collection, pluginname, plugintype, lineno):
        self.collection = collection
        self.pluginname = pluginname
        self.plugintype = plugintype
        self.lineno = lineno


def get_plugin_collection(plugin, plugintype, filectx):
    """Find the collection that the plugin comes from.  Some plugins
    may come from jinja2 e.g. builtin filters and tests.  The plugintype
    field specifies the plugin type - "module" means an Ansible module,
    or one of the jinja2 types like jinja2.nodes.Filter.  If the plugintype
    is an ambiguous type like jinja2.nodes.Call, this function will first
    look for filters, then tests, then lookups."""
    templar = filectx["templar"]
    collection = None
    convert_it = False
    if plugintype == "module":
        ctx = module_loader.find_plugin_with_context(plugin)
        collection = ctx.plugin_resolved_collection
        if not collection:
            raise Exception(f"\tmodule plugin named {plugin} not found")
        return (collection, "module")
    else:
        if plugintype in [jinja2.nodes.Filter, jinja2.nodes.Call]:
            if plugin in jinja2.filters.FILTERS:
                collection = "jinja2.filters"
            else:
                ctx = filter_loader.find_plugin_with_context(plugin)
                collection = ctx.plugin_resolved_collection
                if not collection and plugin in templar.environment.filters:
                    collection = templar.environment.filters[plugin].__module__
                    convert_it = True
                if not collection and plugintype == jinja2.nodes.Filter:
                    raise Exception(f"\tfilter plugin named {plugin} not found")
            if collection:
                returntype = "filter"
        if not collection and plugintype in [jinja2.nodes.Test, jinja2.nodes.Call]:
            if plugin in jinja2.tests.TESTS:
                collection = "jinja2.tests"
            else:
                ctx = test_loader.find_plugin_with_context(plugin)
                collection = ctx.plugin_resolved_collection
                if not collection and plugin in templar.environment.tests:
                    collection = templar.environment.tests[plugin].__module__
                    convert_it = True
                if not collection and plugintype == jinja2.nodes.Test:
                    raise Exception(f"\ttest plugin named {plugin} not found")
                    return (None, "test")
            if collection:
                returntype = "test"
        if not collection and plugintype == jinja2.nodes.Call:
            ctx = lookup_loader.find_plugin_with_context(plugin)
            if ctx.plugin_resolved_collection:
                collection = ctx.plugin_resolved_collection
                returntype = "lookup"
            elif is_builtin(plugin, filectx):
                collection = "ansible.builtin"
                returntype = "lookup"
        if not collection and plugin in jinja2_macros:
            collection = "macro"
            returntype = "macro"
    if not collection:
        raise Exception(f"Error: could not find plugin {plugin}")
    # convert collection to namespace.name format if in python module format
    if convert_it:
        if collection == "genericpath":
            collection = "ansible.builtin"
        elif collection == "json":
            collection = "ansible.builtin"
        elif collection == "ansible.template":
            collection = "ansible.builtin"
        elif collection == "itertools":
            collection = "ansible.builtin"
        elif collection.startswith("ansible_collections.ansible.builtin"):
            collection = "ansible.builtin"
    return (collection, returntype)


def find_plugins(args, filectx):
    templar = filectx["templar"]
    rc = []
    if args is None or not args:
        return rc
    if isinstance(args, str):
        tmpl = templar.environment.parse(source=args)
        node_types = (jinja2.nodes.Call, jinja2.nodes.Filter, jinja2.nodes.Test, jinja2.nodes.Macro)
        for item in tmpl.find_all(node_types):
            if hasattr(item, "name"):
                item_name = item.name
            elif hasattr(item.node, "name"):
                item_name = item.node.name
            elif isinstance(item.node, jinja2.nodes.Getattr):
                logging.debug(f"\tskipping getattr call {item}")
                continue
            else:
                raise Exception(f"\tdo not know what item is {item}")
            if isinstance(item, jinja2.nodes.Macro):
                global jinja2_macros
                jinja2_macros.add(item_name)
                logging.debug(f"\titem {item_name} {item.__class__}")
                continue
            collection, plugintype = get_plugin_collection(item_name, item.__class__, filectx)
            if collection:
                rc.append(PluginItem(collection, item_name, plugintype, filectx.get("lineno", item.lineno)))
            logging.debug(f"\titem [{item_name} {item.__class__} {plugintype}] collection [{collection}]")
            if item_name in ["selectattr", "rejectattr"] and len(item.args) > 1:
                collection, plugintype = get_plugin_collection(item.args[1].value, jinja2.nodes.Test, filectx)
                if collection:
                    rc.append(PluginItem(collection, item.args[1].value, plugintype, filectx.get("lineno", item.lineno)))
                logging.debug(f"\t\targ [{item.args[1].value} {item.__class__} {plugintype}] collection [{collection}]")
            if item_name in ["select", "reject"] and item.args:
                collection, plugintype = get_plugin_collection(item.args[0].value, jinja2.nodes.Test, filectx)
                if collection:
                    rc.append(PluginItem(collection, item.args[0].value, plugintype, filectx.get("lineno", item.lineno)))
                logging.debug(f"\t\targ [{item.args[0].value} {item.__class__} {plugintype}] collection [{collection}]")
            if item_name == "map" and item.args:
                collection, plugintype = get_plugin_collection(item.args[0].value, jinja2.nodes.Filter, filectx)
                if collection:
                    rc.append(PluginItem(collection, item.args[0].value, plugintype, filectx.get("lineno", item.lineno)))
                logging.debug(f"\t\targ [{item.args[0].value} {item.__class__} {plugintype}] collection [{collection}]")
    elif isinstance(args, list):
        for item in args:
            rc.extend(find_plugins(item, filectx))
    elif isinstance(args, dict):
        for item in args.values():
            rc.extend(find_plugins(item, filectx))
    elif isinstance(args, (bool, int, float)):
        pass
    else:
        raise Exception(f"ERROR: I don't know how to handle {args.__class__}")
    return rc


def find_plugins_for_when_that(val, filectx):
    """when or that - val can be string or list"""
    rc = []
    if isinstance(val, list):
        for item in val:
            rc.extend(find_plugins_for_when_that(item, filectx))
    elif isinstance(val, (bool, int, float)):
        pass
    else:
        templar = filectx["templar"]
        if templar.is_template(val):
            rc.extend(find_plugins(val, filectx))
        else:
            rc.extend(find_plugins("{{ " + val + " }}", filectx))
    return rc


def handle_task(task, filectx):
    """handle a single task"""
    mod_arg_parser = ModuleArgsParser(task)
    plugins = []
    try:
        action, args, _ = mod_arg_parser.parse(skip_action_validation=True)
    except AnsibleParserError as e:
        raise SystemExit("Couldn't parse task at %s (%s)\n%s" % (task, e.message, task))
    templar = filectx["templar"]
    filectx["lineno"] = task.ansible_pos[1]
    if templar.is_template(args):
        logging.debug(f"\tmodule {action} has template {args}")
        plugins = find_plugins(args, filectx)
    elif action == "assert":
        plugins = find_plugins_for_when_that(args["that"], filectx)
    else:
        logging.debug(f"\tmodule {action} has no template {args}")
    if "when" in task:
        plugins.extend(find_plugins_for_when_that(task["when"], filectx))
    if action == "include_role" or action == "import_role":
        logging.debug(f"\ttask role {task[action]['name']}")
        plugins.append(PluginItem("ansible.builtin", action, "module", task.ansible_pos[1]))
    elif action in filectx["role_modules"]:
        logging.debug(f"\ttask role module {action}")
    else:
        collection, plugintype = get_plugin_collection(action, "module", filectx)
        plugins.append(PluginItem(collection, action, plugintype, task.ansible_pos[1]))
    filectx["plugins"].extend(plugins)


def handle_tasks(item, filectx):
    """item has one or more fields which hold a list of Task objects"""
    for kw in TASK_LIST_KWS:
        if kw in item:
            for task in item[kw]:
                handle_item(task, filectx)


def handle_item(item, filectx):
    handle_vars(item, filectx)
    item_type = get_item_type(item)
    if item_type == "task":
        handle_task(item, filectx)
    else:
        handle_other(item, filectx)
    handle_tasks(item, filectx)


def parse_role(role_path):
    role_plugins = []
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
            fpth = Path(filepath)
            relpth = str(fpth.relative_to(Path(role_path)))
            filectx = {"role_modules": role_modules, "templar": Templar(loader=None), "plugins": []}
            logging.debug(f"filepath {filepath}")
            if role_dir == "templates":
                logging.debug(f"handle template {filepath}")
                plugins = find_plugins(open(filepath).read(), filectx)
            elif filepath.endswith(".yml"):
                dl = DataLoader()
                ans_data = dl.load_from_file(filepath)
                if ans_data is None:
                    logging.debug(f"file is empty {filepath}")
                    continue
                file_type = get_file_type(ans_data)
                if file_type == "vars":
                    handle_vars(ans_data, filectx)
                elif file_type == "meta":
                    handle_meta(ans_data, filectx)
                else:
                    for item in ans_data:
                        handle_item(item, filectx)
                plugins = filectx.get("plugins", [])
            else:
                continue
            if plugins:
                for item in plugins:
                    item.role = role_name
                    item.filepath = relpth
                    logging.debug(f"\t{role_name} {item.collection} {item.pluginname} {item.plugintype} {relpth}:{item.lineno}")
                    if relpth.startswith("tests/"):
                        item.testing = True
                    else:
                        item.testing = False
            else:
                logging.debug("\tno plugins")
            role_plugins.extend(plugins)
    return role_plugins


if __name__ == "__main__":
    all_plugins = []
    testing_plugins = {}
    runtime_plugins = {}
    for role_path in sys.argv[1:]:
        all_plugins.extend(parse_role(role_path))
    for item in all_plugins:
        if item.plugintype == "macro":
            continue
        key = item.collection + "." + item.pluginname + ":" + item.plugintype
        if item.testing:
            hsh = testing_plugins
        else:
            hsh = runtime_plugins
        subitem = hsh.setdefault(key, {"roles": set()})
        subitem["name"] = item.pluginname
        subitem["type"] = item.plugintype
        subitem["collection"] = item.collection
        subitem["roles"].add(item.role)
    print("These plugins are used at runtime: ")
    for key in sorted(runtime_plugins):
        item = runtime_plugins[key]
        print(f"{item['collection']}.{item['name']} type: {item['type']} roles: {' '.join(sorted(item['roles']))}")
    print("\nThese plugins are used in testing: ")
    for key in sorted(testing_plugins):
        item = testing_plugins[key]
        print(f"{item['collection']}.{item['name']} type: {item['type']} roles: {' '.join(sorted(item['roles']))}")
