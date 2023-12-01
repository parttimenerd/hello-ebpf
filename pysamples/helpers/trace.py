"""
Collects and prints information about used classes and functions.

Usage:
    import trace
    trace.setup(r"MODULE_REGEX")
    ...

This prints information about used classes and functions on exit.

LICENSE: MIT
"""

import inspect
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import FrameType, CodeType
from typing import Set, Dict, List
import atexit

STATIC_INIT = "<static init>"


def log(message: str):
    print(message, file=sys.stderr)


@dataclass
class ClassInfo:
    """ Used methods of a class """
    name: str
    used_methods: Set[str] = field(default_factory=set)

    def log(self, indent_: str):
        log(indent_ + self.name)
        for method in sorted(self.used_methods):
            log(indent_ + "  " + method)

    def has_only_static_init(self) -> bool:
        return (
                len(self.used_methods) == 1 and
                self.used_methods.pop() == STATIC_INIT)


indent = 0
used_classes: Dict[str, ClassInfo] = {}
free_functions: Set[str] = set()
module_matcher: str = ".*"
print_location: bool = False


def classes_sorted_by_name() -> List[ClassInfo]:
    return sorted(used_classes.values(), key=lambda x: x.name)


def print_info():
    only_static_init = []
    not_only_static_init = []
    for class_info in classes_sorted_by_name():
        if class_info.has_only_static_init():
            only_static_init.append(class_info)
        else:
            not_only_static_init.append(class_info)
    log("Used classes:")
    log("  only static init:")
    for class_info in only_static_init:
        log("    " + class_info.name)
    log("  not only static init:")
    for class_info in not_only_static_init:
        class_info.log(" " * 3)
    log("Free functions:")
    for free_function in sorted(free_functions):
        log("  " + free_function)


def get_class_info(class_name: str) -> ClassInfo:
    if class_name not in used_classes:
        used_classes[class_name] = ClassInfo(class_name)
    return used_classes[class_name]


class StaticFunctionType(Enum):
    INIT = 1
    """ static init """
    STATIC = 2
    """ static function """
    FREE = 3
    """ free function, not related to a class """


def get_static_type(code: CodeType) -> StaticFunctionType:
    file_lines = Path(code.co_filename).read_text().split("\n")
    line = code.co_firstlineno
    header_line = file_lines[line - 1]
    if "class " in header_line:
        return StaticFunctionType.INIT
    if "@staticmethod" in header_line:
        return StaticFunctionType.STATIC
    return StaticFunctionType.FREE


def insert_class_or_instance_function(module_name: str,
                                      func_name: str,
                                      frame: FrameType) -> str:
    """
    Insert the code object of an instance or class function and
    return the name to print
    """
    class_name = ""
    if "self" in frame.f_locals:
        class_name = frame.f_locals["self"].__class__.__name__
    elif "cls" in frame.f_locals:
        class_name = frame.f_locals["cls"].__name__
        func_name = "<class>" + func_name
    class_name = module_name + "." + class_name
    get_class_info(class_name).used_methods.add(func_name)
    used_classes[class_name].used_methods.add(func_name)
    return class_name + "." + func_name


def insert_class_or_function(module_name: str, func_name: str,
                             frame: FrameType) -> str:
    """ Insert the code object and return the name to print """
    if "self" in frame.f_locals or "cls" in frame.f_locals:
        return insert_class_or_instance_function(module_name,
                                                 func_name, frame)
    t = get_static_type(frame.f_code)
    if t == StaticFunctionType.INIT:
        class_name = module_name + "." + func_name
        get_class_info(class_name).used_methods.add(STATIC_INIT)
        return class_name + "." + STATIC_INIT
    elif t == StaticFunctionType.STATIC:
        class_name = module_name + "." + frame.f_code.co_qualname[
                                         :-len(func_name) - 1]
        func_name = "<static>" + func_name
        get_class_info(class_name).used_methods.add(func_name)
        return class_name + "." + func_name
    free_functions.add(frame.f_code.co_name)
    return module_name + "." + func_name


def do_print_location(frame: FrameType):
    """ Print the location of the frame """
    log(" " * indent + frame.f_code.co_filename + ":" + str(
        frame.f_lineno))


def handler(frame: FrameType, event: str, *args):
    """ Trace handler that prints and tracks called functions """
    module_name: str = mod.__name__ if (
        mod := inspect.getmodule(frame.f_code)) else ""
    func_name = frame.f_code.co_name
    if not re.match(module_matcher, module_name):
        return
    global indent
    if event == 'return':
        indent -= 2
        return
    if event != "call":
        return
    name = insert_class_or_function(module_name, func_name, frame)
    if print_location:
        do_print_location(frame)
    log(" " * indent + name)
    indent += 2
    return handler


def setup(module_matcher_: str = ".*", print_location_: bool = False):
    """
    Set up the tracer
    :param module_matcher_: regex to match module names
    :param print_location_: print location of every function?
    :return:
    """
    global module_matcher, print_location
    module_matcher = module_matcher_
    print_location = print_location_
    sys.settrace(handler)


def teardown():
    """ Teardown the tracer and print the results """
    sys.settrace(None)
    log("********** Trace Results **********")
    print_info()


# trigger teardown on exit
atexit.register(teardown)
