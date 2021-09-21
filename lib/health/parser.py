# Copyright 2013-2021 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import re

from .exceptions import SyntaxException
from . import commands
from . import constants
from . import operation
from . import util

try:
    from ply import lex, yacc
except Exception:
    pass

HealthVars = {}


class HealthLexer:
    SNAPSHOT_KEY_PATTERN = r"SNAPSHOT(\d+)$"

    assert_levels = {
        "CRITICAL": constants.AssertLevel.CRITICAL,
        "WARNING": constants.AssertLevel.WARNING,
        "INFO": constants.AssertLevel.INFO,
    }

    components = {
        "ALL": "ALL",
        "ASD_PROCESS": "ASD_PROCESS",
        "AVG-CPU": "AVG-CPU",
        "BIN": "BIN",
        "BUFFERS/CACHE": "BUFFERS/CACHE",
        "CONFIG": "CONFIG",
        "CPU_UTILIZATION": "CPU_UTILIZATION",
        "DEVICE_INTERRUPTS": "DEVICE_INTERRUPTS",
        "DEVICE_STAT": "DEVICE_STAT",
        "DF": "DF",
        "DMESG": "DMESG",
        "ENDPOINTS": "ENDPOINTS",
        "ENVIRONMENT": "ENVIRONMENT",
        "FREE": "FREE",
        "HDPARM": "HDPARM",
        "HEALTH": "HEALTH",
        "INTERRUPTS": "INTERRUPTS",
        "IOSTAT": "IOSTAT",
        "IPTABLES": "IPTABLES",
        "LIMITS": "LIMITS",
        "LSB": "LSB",
        "LSCPU": "LSCPU",
        "MEM": "MEM",
        "MEMINFO": "MEMINFO",
        "METADATA": "METADATA",
        "NETWORK": "NETWORK",
        "ORIGINAL_CONFIG": "ORIGINAL_CONFIG",
        "RAM": "RAM",
        "ROLES": "ROLES",
        "ROSTER": "ROSTER",
        "SYSTEM": "SYSTEM",
        "SECURITY": "SECURITY",
        "SERVICE": "SERVICE",
        "SERVICES": "SERVICES",
        "SCHEDULER": "SCHEDULER",
        "STATISTICS": "STATISTICS",
        "SWAP": "SWAP",
        "SYSCTLALL": "SYSCTLALL",
        "TASKS": "TASKS",
        "TOP": "TOP",
        "UDF": "UDF",
        "UPTIME": "UPTIME",
        "USERS": "USERS",
        "XDR": "XDR",
        "XDR_PROCESS": "XDR_PROCESS",
    }

    group_ids = {
        "BUCKET_END": "BUCKET_END",
        "BUCKET_START": "BUCKET_START",
        "CLUSTER": "CLUSTER",
        "DEVICE": "DEVICE",
        "FILENAME": "FILENAME",
        "FILE_SYSTEM": "FILE_SYSTEM",
        "INTERRUPT_DEVICE": "INTERRUPT_DEVICE",
        "INTERRUPT_ID": "INTERRUPT_ID",
        "INTERRUPT_TYPE": "INTERRUPT_TYPE",
        "KEY": "KEY",
        "NODE": "NODE",
        "OUTLIER": "OUTLIER",
        "SNAPSHOT": "SNAPSHOT",
    }

    component_and_group_id = {
        "DC": "DC",
        "HISTOGRAM": "HISTOGRAM",
        "NAMESPACE": "NAMESPACE",
        "RACKS": "RACKS",
        "SET": "SET",
        "SINDEX": "SINDEX",
    }

    agg_ops = {
        "AND": "AND",
        "AVG": "AVG",
        "COUNT": "COUNT",
        "COUNT_ALL": "COUNT_ALL",
        "EQUAL": "EQUAL",
        "MAX": "MAX",
        "MIN": "MIN",
        "OR": "OR",
        "FIRST": "FIRST",
        "SUM": "SUM",
        "VALUE_UNIFORM": "VALUE_UNIFORM",
    }

    complex_ops = {"DIFF": "DIFF", "SD_ANOMALY": "SD_ANOMALY", "NO_MATCH": "NO_MATCH"}

    apply_ops = {"APPLY_TO_ANY": "APPLY_TO_ANY", "APPLY_TO_ALL": "APPLY_TO_ALL"}

    simple_ops = {"SPLIT": "SPLIT", "UNIQUE": "UNIQUE"}

    complex_params = {
        "MAJORITY": constants.MAJORITY,
    }

    assert_ops = {"ASSERT": "ASSERT"}

    bool_vals = {"true": True, "false": False}

    reserved = {
        "as": "AS",
        "by": "BY",
        "common": "COMMON",
        "do": "DO",
        "from": "FROM",
        "group": "GROUP",
        "ignore": "IGNORE",
        "like": "LIKE",
        "on": "ON",
        "save": "SAVE",
        "select": "SELECT",
    }

    tokens = [
        "NUMBER",
        "FLOAT",
        "BOOL_VAL",
        "VAR",
        "NEW_VAR",
        "COMPONENT",
        "GROUP_ID",
        "COMPONENT_AND_GROUP_ID",
        "AGG_OP",
        "COMPLEX_OP",
        "APPLY_OP",
        "SIMPLE_OP",
        "COMPLEX_PARAM",
        "ASSERT_OP",
        "ASSERT_LEVEL",
        "STRING",
        "COMMA",
        "DOT",
        "IN",
        "PLUS",
        "MINUS",
        "TIMES",
        "DIVIDE",
        "BINARY_AND",
        "BINARY_OR",
        "LPAREN",
        "RPAREN",
        "GT",
        "GE",
        "LT",
        "LE",
        "EQ",
        "NE",
        "ASSIGN",
        "PCT",
    ] + list(reserved.values())

    def t_FLOAT(self, t):
        r"\d+(\.(\d+)?([eE][-+]?\d+)?|[eE][-+]?\d+)"
        t.value = float(t.value)
        return t

    def t_NUMBER(self, t):
        r"\d+"
        t.value = int(t.value)
        return t

    def t_VAR(self, t):
        r"[a-zA-Z_][a-zA-Z_0-9]*"
        # Check for reserved words
        t.type = HealthLexer.reserved.get(t.value.lower(), "NEW_VAR")
        if not t.type == "NEW_VAR":
            return t
        elif t.value.lower() in HealthLexer.bool_vals.keys():
            t.type = "BOOL_VAL"
            t.value = HealthLexer.bool_vals.get(t.value.lower())
        elif re.match(HealthLexer.SNAPSHOT_KEY_PATTERN, t.value):
            t.value = util.create_snapshot_key(
                int(re.search(HealthLexer.SNAPSHOT_KEY_PATTERN, t.value).group(1))
            )
            t.type = "COMPONENT"
        elif t.value in HealthLexer.components.keys():
            t.type = "COMPONENT"
        elif t.value in HealthLexer.group_ids.keys():
            t.type = "GROUP_ID"
        elif t.value in HealthLexer.component_and_group_id:
            t.type = "COMPONENT_AND_GROUP_ID"
        elif t.value in HealthLexer.agg_ops.keys():
            t.type = "AGG_OP"
        elif t.value in HealthLexer.complex_ops.keys():
            t.type = "COMPLEX_OP"
        elif t.value in HealthLexer.apply_ops.keys():
            t.type = "APPLY_OP"
        elif t.value in HealthLexer.simple_ops.keys():
            t.type = "SIMPLE_OP"
        elif t.value == "IN":
            t.type = "IN"
        elif t.value in HealthLexer.complex_params.keys():
            t.value = HealthLexer.complex_params[t.value]
            t.type = "COMPLEX_PARAM"
        elif t.value in HealthLexer.assert_ops.keys():
            t.type = "ASSERT_OP"
        elif t.value in HealthLexer.assert_levels.keys():
            t.value = HealthLexer.assert_levels[t.value]
            t.type = "ASSERT_LEVEL"
        elif t.value in HealthVars:
            t.type = "VAR"
            t.value = (
                constants.HEALTH_PARSER_VAR,
                t.value,
                copy.deepcopy(HealthVars[t.value]),
            )
        return t

    def t_STRING(self, t):
        r"\".*?\" "
        if len(t.value) < 3:
            t.value = None
        else:
            t.value = t.value[1 : len(t.value) - 1]
        return t

    # Define a rule so we can track line numbers
    def t_newline(self, t):
        r"\n+"
        t.lexer.lineno += len(t.value)

    t_ignore = " \t"

    # Regular expression rules for simple tokens
    t_COMMA = r"\,"
    t_DOT = r"\."
    t_PLUS = r"\+"
    t_MINUS = r"-"
    t_PCT = r"%%"
    t_TIMES = r"\*"
    t_DIVIDE = r"/"
    t_BINARY_OR = r"\|\|"
    t_BINARY_AND = r"&&"
    t_LPAREN = r"\("
    t_RPAREN = r"\)"
    t_GT = r">"
    t_GE = r">="
    t_LT = r"<"
    t_LE = r"<="
    t_EQ = r"=="
    t_NE = r"!="
    t_ASSIGN = r"="

    def t_error(self, t):
        raise TypeError("Unknown text '%s'" % (t.value,))

    def build(self, **kwargs):
        self.lexer = lex.lex(module=self, **kwargs)
        return self.lexer


class HealthParser:

    tokens = HealthLexer.tokens
    health_input_data = {}

    precedence = (
        ("left", "ASSIGN"),
        ("left", "BINARY_OR"),
        ("left", "BINARY_AND"),
        ("left", "EQ", "NE", "LT", "GT", "LE", "GE"),
        ("left", "PLUS", "MINUS"),
        ("left", "TIMES", "DIVIDE"),
        ("left", "PCT"),
    )

    def p_statement(self, p):
        """
        statement : VAR opt_assign_statement
                   | NEW_VAR assign_statement
                   | assert_statement
        """
        if len(p) > 2 and p[2] is not None:
            if isinstance(p[2], Exception):
                val = None
            elif util.is_health_parser_variable(p[2]):
                val = p[2][2]
            else:
                val = p[2]

            if util.is_health_parser_variable(p[1]):
                HealthVars[p[1][1]] = val
            else:
                HealthVars[p[1]] = val
            p[0] = val
            if isinstance(p[2], Exception):
                raise p[2]
        else:
            p[0] = p[1]

    def p_binary_operation(self, p):
        """
        binary_operation : operand op operand opt_on_clause
        """
        p[0] = (p[2], p[1], p[3], None, None, p[4])

    def p_opt_on_clause(self, p):
        """
        opt_on_clause : ON COMMON
                         |
        """
        if len(p) == 1:
            p[0] = False
        else:
            p[0] = True

    def p_agg_operation(self, p):
        """
        agg_operation : AGG_OP LPAREN operand RPAREN
        """
        p[0] = (p[1], p[3], None, None, None, False)

    def p_complex_operation(self, p):
        """
        complex_operation : COMPLEX_OP LPAREN operand COMMA comparison_op COMMA complex_comparison_operand RPAREN
        """
        p[0] = (p[1], p[3], None, p[5], p[7], False)

    def p_apply_operation(self, p):
        """
        apply_operation : APPLY_OP LPAREN operand COMMA apply_comparison_op COMMA operand RPAREN
        """
        p[0] = (p[1], p[3], p[7], p[5], None, False)

    def p_simple_operation(self, p):
        """
        simple_operation : SIMPLE_OP LPAREN operand opt_simple_operation_param RPAREN
        """
        p[0] = (p[1], p[3], p[4], None, None, False)

    def p_opt_simple_operation_param(self, p):
        """
        opt_simple_operation_param : COMMA constant
                         |
        """
        if len(p) == 1:
            p[0] = None
        else:
            p[0] = util.create_health_internal_tuple(p[2], [])

    def p_apply_comparison_op(self, p):
        """
        apply_comparison_op : IN
                              | comparison_op
        """
        p[0] = p[1]

    def p_complex_comparison_operand(self, p):
        """
        complex_comparison_operand : COMPLEX_PARAM
                   | operand
        """
        if util.is_health_parser_variable(p[1]):
            p[0] = p[1][2]

        elif not isinstance(p[1], tuple):
            p[0] = util.create_health_internal_tuple(p[1], [])

        else:
            p[0] = p[1]

    def p_operand(self, p):
        """
        operand : VAR
                   | constant
        """
        if util.is_health_parser_variable(p[1]):
            p[0] = p[1][2]
        else:
            p[0] = util.create_health_internal_tuple(p[1], [])

    def p_value(self, p):
        """
        value : NUMBER
                | FLOAT
        """
        p[0] = p[1]

    def p_number(self, p):
        """
        number : value
                   | PLUS value
                   | MINUS value
        """
        if len(p) == 2:
            p[0] = p[1]
        elif p[1] == "-":
            p[0] = p[2] * -1
        else:
            p[0] = p[2]

    def p_op(self, p):
        """
        op : PLUS
            | MINUS
            | TIMES
            | DIVIDE
            | PCT
            | comparison_op
            | BINARY_AND
            | BINARY_OR
            | IN

        """
        p[0] = p[1]

    def p_comparison_op(self, p):
        """
        comparison_op : EQ
                        | NE
                        | LT
                        | GT
                        | LE
                        | GE

        """
        p[0] = p[1]

    def p_group_by_clause(self, p):
        """
        group_by_clause : GROUP BY group_by_ids
        """
        p[0] = p[3]

    def p_group_by_ids(self, p):
        """
        group_by_ids : group_by_ids COMMA group_by_id
                          | group_by_id
        """
        if len(p) > 2:
            p[1].append(p[3])
            p[0] = p[1]
        else:
            p[0] = [p[1]]

    def p_group_by_id(self, p):
        """
        group_by_id : GROUP_ID
                       | COMPONENT_AND_GROUP_ID
        """
        p[0] = p[1]

    def p_opt_group_by_clause(self, p):
        """
        opt_group_by_clause : group_by_clause
                         |
        """
        if len(p) == 1:
            p[0] = None
        else:
            p[0] = p[1]

    def p_group_by_statement(self, p):
        """
        group_by_statement : group_by_clause VAR
        """
        try:
            p[0] = operation.do_multiple_group_by(p[2][2], p[1])
        except Exception as e:
            p[0] = e

    def p_opt_assign_statement(self, p):
        """
        opt_assign_statement : assign_statement
                                |
        """
        if len(p) > 1:
            p[0] = p[1]
        else:
            p[0] = None

    def p_assign_statement(self, p):
        """
        assign_statement : ASSIGN cmd_statement
        """
        p[0] = p[2]

    def p_cmd_statement(self, p):
        """
        cmd_statement : select_statement
                        | op_statement
                        | group_by_statement
        """
        p[0] = p[1]

    def p_op_statement(self, p):
        """
        op_statement : opt_group_by_clause DO binary_operation opt_save_clause
                        | opt_group_by_clause DO agg_operation opt_save_clause
                        | opt_group_by_clause DO complex_operation opt_save_clause
                        | opt_group_by_clause DO apply_operation opt_save_clause
                        | opt_group_by_clause DO simple_operation opt_save_clause
        """
        try:
            p[0] = commands.do_operation(
                op=p[3][0],
                arg1=p[3][1],
                arg2=p[3][2],
                group_by=p[1],
                result_comp_op=p[3][3],
                result_comp_val=p[3][4],
                on_common_only=p[3][5],
                save_param=p[4],
            )
        except Exception as e:
            p[0] = e

    def p_opt_save_clause(self, p):
        """
        opt_save_clause : SAVE opt_as_clause
                         |
        """
        if len(p) == 3:
            if p[2] is None:
                # No keyname entered so use same as value keyname
                p[0] = ""
            else:
                # Keyname entered
                p[0] = p[2]
        else:
            # No data saving
            p[0] = None

    def p_assert_statement(self, p):
        """
        assert_statement : ASSERT_OP LPAREN assert_arg COMMA assert_comparison_arg COMMA error_string COMMA assert_category COMMA ASSERT_LEVEL COMMA assert_desc_string COMMA assert_success_msg COMMA assert_if_condition RPAREN
                             | ASSERT_OP LPAREN assert_arg COMMA assert_comparison_arg COMMA error_string COMMA assert_category COMMA ASSERT_LEVEL COMMA assert_desc_string COMMA assert_success_msg RPAREN
                             | ASSERT_OP LPAREN assert_arg COMMA assert_comparison_arg COMMA error_string COMMA assert_category COMMA ASSERT_LEVEL COMMA assert_desc_string RPAREN
                             | ASSERT_OP LPAREN assert_arg COMMA assert_comparison_arg COMMA error_string COMMA assert_category COMMA ASSERT_LEVEL RPAREN
        """
        if len(p) < 14:
            p[0] = commands.do_assert(
                op=p[1],
                data=p[3],
                check_val=p[5],
                error=p[7],
                category=p[9],
                level=p[11],
            )
        elif len(p) < 16:
            p[0] = commands.do_assert(
                op=p[1],
                data=p[3],
                check_val=p[5],
                error=p[7],
                category=p[9],
                level=p[11],
                description=p[13],
            )
        elif len(p) < 18:
            p[0] = commands.do_assert(
                op=p[1],
                data=p[3],
                check_val=p[5],
                error=p[7],
                category=p[9],
                level=p[11],
                description=p[13],
                success_msg=p[15],
            )
        else:
            skip_assert, assert_filter_arg = p[17]
            if skip_assert:
                p[0] = None
            else:
                if assert_filter_arg is not None:
                    data = commands.do_operation(op="==", arg1=p[3], arg2=p[5])
                    try:
                        # If key filtration throws exception (due to non-matching), it just passes that and executes main assert
                        new_data = commands.do_operation(
                            op="||",
                            arg1=data,
                            arg2=assert_filter_arg,
                            on_common_only=True,
                        )
                        if new_data:
                            data = new_data
                    except Exception:
                        pass

                    p[0] = commands.do_assert(
                        op=p[1],
                        data=data,
                        check_val=util.create_health_internal_tuple(True, []),
                        error=p[7],
                        category=p[9],
                        level=p[11],
                        description=p[13],
                        success_msg=p[15],
                    )
                else:
                    p[0] = commands.do_assert(
                        op=p[1],
                        data=p[3],
                        check_val=p[5],
                        error=p[7],
                        category=p[9],
                        level=p[11],
                        description=p[13],
                        success_msg=p[15],
                    )

    def p_assert_if_condition(self, p):
        """
        assert_if_condition : assert_arg opt_assert_if_arg2
        """
        skip_assert, assert_filter_arg = commands.do_assert_if_check(
            p[2][0], p[1], p[2][1]
        )
        p[0] = (skip_assert, assert_filter_arg)

    def p_opt_assert_if_arg2(self, p):
        """
        opt_assert_if_arg2 : comparison_op assert_arg
                            |
        """
        if len(p) > 1:
            p[0] = (p[1], p[2])
        else:
            p[0] = (None, None)

    def p_assert_arg(self, p):
        """
        assert_arg : operand
        """
        p[0] = p[1]

    def p_assert_comparison_arg(self, p):
        """
        assert_comparison_arg : constant
        """
        p[0] = util.create_health_internal_tuple(p[1], [])

    def p_constant(self, p):
        """
        constant : number
                    | STRING
                    | BOOL_VAL
        """
        p[0] = util.h_eval(p[1])

    def p_assert_category(self, p):
        """
        assert_category : STRING
        """
        p[0] = p[1]

    def p_assert_desc_string(self, p):
        """
        assert_desc_string : NUMBER
                        | STRING
        """
        p[0] = p[1]

    def p_assert_success_msg(self, p):
        """
        assert_success_msg : NUMBER
                        | STRING
        """
        p[0] = p[1]

    def p_error_string(self, p):
        """
        error_string : NUMBER
                        | STRING
        """
        p[0] = p[1]

    def p_select_statement(self, p):
        """
        select_statement : SELECT select_keys opt_from_clause opt_ignore_clause opt_save_clause
                          | operand
        """
        if len(p) > 2:
            try:
                p[0] = commands.select_keys(
                    data=self.health_input_data,
                    select_keys=p[2],
                    select_from_keys=p[3],
                    ignore_keys=p[4],
                    save_param=p[5],
                )
            except Exception as e:
                p[0] = e
        else:
            p[0] = p[1]

    def p_opt_from_clause(self, p):
        """
        opt_from_clause : FROM opt_snapshot_var select_from_keys
                         |
        """
        if len(p) == 1:
            p[0] = None
        else:
            p[0] = p[2] + p[3]

    def p_opt_snapshot_var(self, p):
        """
        opt_snapshot_var : VAR opt_dot
                         |
        """
        if len(p) == 1:
            p[0] = []
        elif re.match(HealthLexer.SNAPSHOT_KEY_PATTERN, p[1][1]):
            p[0] = [p[1][1]]
        else:
            raise SyntaxException("Wrong snapshot component " + p[1][1])

    def p_opt_dot(self, p):
        """
        opt_dot : DOT
                  |
        """
        if len(p) == 1:
            p[0] = None
        else:
            p[0] = p[1]

    def p_select_from_keys(self, p):
        """
        select_from_keys : select_from_keys DOT select_from_key
                          | select_from_key
        """
        if len(p) > 2:
            p[1].append(p[3])
            p[0] = p[1]
        else:
            p[0] = [p[1]]

    def p_select_from_key(self, p):
        """
        select_from_key : COMPONENT
                    | COMPONENT_AND_GROUP_ID
        """
        p[0] = p[1]

    def p_opt_as_clause(self, p):
        """
        opt_as_clause : AS STRING
                         |
        """
        if len(p) == 1:
            p[0] = None
        else:
            p[0] = p[2]

    def p_select_keys(self, p):
        """
        select_keys : select_keys COMMA select_key
                      | select_key
        """
        if len(p) > 2:
            p[1].append(p[3])
            p[0] = p[1]
        else:
            p[0] = [p[1]]

    def p_select_key(self, p):
        """
        select_key : LIKE LPAREN key RPAREN opt_as_clause
                      | key opt_as_clause
        """
        if len(p) > 3:
            pattern = p[3]
            if not pattern.startswith("^"):
                pattern = "^" + str(pattern)
            if not pattern.endswith("$"):
                pattern += "$"
            p[0] = (True, pattern, p[5])
        else:
            p[0] = (False, p[1], p[2])

    def p_opt_ignore_clause(self, p):
        """
        opt_ignore_clause : IGNORE ignore_keys
                         |
        """
        if len(p) == 1:
            p[0] = []
        else:
            p[0] = p[2]

    def p_ignore_keys(self, p):
        """
        ignore_keys : ignore_keys COMMA ignore_key
                      | ignore_key
        """
        if len(p) > 2:
            p[1].append(p[3])
            p[0] = p[1]
        else:
            p[0] = [p[1]]

    def p_ignore_key(self, p):
        """
        ignore_key : LIKE LPAREN key RPAREN
                      | key
        """
        if len(p) > 2:
            pattern = p[3]
            if not pattern.startswith("^"):
                pattern = "^" + str(pattern)
            if not pattern.endswith("$"):
                pattern += "$"
            p[0] = (True, pattern)
        else:
            p[0] = (False, p[1])

    def p_key(self, p):
        """
        key : STRING
               | TIMES
        """
        p[0] = p[1]

    def p_error(self, p):
        if p:
            raise SyntaxException(
                "Syntax error at position %d : %s" % ((p.lexpos), str(p))
            )
        else:
            raise SyntaxException("Syntax error : Insufficient tokens")

    def build(self, **kwargs):
        self.parser = yacc.yacc(
            module=self,
            debug=False,
            write_tables=False,
            errorlog=yacc.NullLogger(),
            **kwargs
        )
        self.lexer = HealthLexer().build()
        return self.parser

    def set_health_data(self, health_input_data):
        self.health_input_data = health_input_data

    def clear_health_cache(self):
        global HealthVars
        HealthVars = {}

    def parse(self, text):
        return self.parser.parse(text, lexer=self.lexer)
