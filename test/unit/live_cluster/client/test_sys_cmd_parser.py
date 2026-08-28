# Copyright 2026 Aerospike, Inc.
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

import unittest

from lib.live_cluster.client import sys_cmd_parser

TOP_HEADER = """top - 05:33:44 up 9 min,  0 users,  load average: 1.29, 1.34, 1.35
Tasks: 149 total,   1 running, 148 sleeping,   0 stopped,   0 zombie
%Cpu(s): 11.3 us,  1.0 sy,  0.0 ni, 85.0 id,  1.7 wa,  0.0 hi,  0.7 si,  0.3 st
KiB Mem : 62916356 total, 54829756 used,  8086600 free,   194440 buffers
KiB Swap:        0 total,        0 free,        0 used. 52694652 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"""

ASD_LINE = "  26937 root      20   0 59.975g 0.049t 0.048t S 117.6  83.9 164251:27 asd"


def _idle_kernel_threads(count):
    return [
        "     {:>3} root      20   0       0      0      0 S   0.0   0.0   0:00.00 "
        "kworker+".format(pid)
        for pid in range(2, 2 + count)
    ]


def _top_output(leading_processes):
    lines = [TOP_HEADER]
    lines.extend(_idle_kernel_threads(leading_processes))
    lines.append(ASD_LINE)
    return "\n".join(lines)


class ParseTopSectionTest(unittest.TestCase):
    def test_asd_process_parsed_when_listed_first(self):
        result = sys_cmd_parser.parse_top_section(_top_output(0))

        self.assertEqual(result["asd_process"]["resident_memory"], 53876069761)
        self.assertEqual(result["asd_process"]["%cpu"], "117.6")
        self.assertEqual(result["asd_process"]["%mem"], "83.9")

    def test_asd_process_parsed_wherever_top_ranks_it(self):
        """
        'top -n1 -b' reports %CPU as a since-boot average, so the first
        iteration lists processes by pid and asd sits below every kernel
        thread. Health reads resident_memory from this section, so a cutoff
        near the top of the listing drops it on every live-mode run.
        """
        for leading_processes in (24, 25, 26, 200):
            with self.subTest(leading_processes=leading_processes):
                result = sys_cmd_parser.parse_top_section(
                    _top_output(leading_processes)
                )

                self.assertEqual(result["asd_process"]["resident_memory"], 53876069761)

    def test_command_matched_exactly_not_by_substring(self):
        """
        'dasd' on macOS and any user process whose name contains 'asd' would
        otherwise be read as the server, filling asd_process from the wrong
        row.
        """
        for command in ("dasd", "fasd", "asdf", "my-asd-wrapper"):
            with self.subTest(command=command):
                lines = [TOP_HEADER, ASD_LINE.replace(" asd", " " + command)]
                result = sys_cmd_parser.parse_top_section("\n".join(lines))

                self.assertEqual(result["asd_process"], {})

    def test_summary_comes_from_the_first_iteration(self):
        """
        'top -n3' repeats its summary per iteration while live mode runs
        'top -n1'. Reading past the first block would leave the two modes
        describing different samples of the same node.
        """
        second_iteration = (
            TOP_HEADER.replace(
                "62916356 total, 54829756 used", "62916356 total, 1 used"
            )
            .replace("Tasks: 149 total", "Tasks: 150 total")
            .replace("11.3 us", "99.9 us")
            .replace("52694652 avail Mem", "1 avail Mem")
        )
        result = sys_cmd_parser.parse_top_section(
            "\n".join([_top_output(30), second_iteration, ASD_LINE])
        )

        self.assertEqual(result["tasks"]["total"], "149")
        self.assertEqual(result["cpu_utilization"]["us"], "11.3")
        self.assertEqual(result["ram"]["used"], 54829756 * 1024)
        self.assertEqual(result["swap"]["avail"], 52694652 * 1024)

    def test_short_lines_do_not_raise(self):
        lines = [TOP_HEADER, "   1 root asd", "garbage", "", ASD_LINE]
        result = sys_cmd_parser.parse_top_section("\n".join(lines))

        self.assertEqual(result["asd_process"]["resident_memory"], 53876069761)

    def test_mac_top_output_yields_no_asd_process(self):
        """
        'top -l 1' prints entirely different columns, so no row should be read
        as the server rather than a row being read with the wrong fields.
        """
        header = (
            "Processes: 797 total, 3 running, 794 sleeping, 5210 threads\n"
            "Load Avg: 3.03, 5.13, 5.18\n"
            "CPU usage: 5.65% user, 10.97% sys, 83.37% idle\n"
            "PhysMem: 35G used (3185M wired, 10G compressor), 756M unused.\n"
            "PID    COMMAND          %CPU TIME     #TH #WQ #PORTS MEM   PURG "
            "CMPRS PGRP  PPID  STATE\n"
        )
        rows = (
            "441    dasd             0.0  00:12.35 3   1   62     3760K 0B   "
            "1424K 441   1     sleeping\n"
        )
        result = sys_cmd_parser.parse_top_section(header + rows)

        self.assertEqual(result["asd_process"], {})

    def test_header_fields_still_parsed(self):
        result = sys_cmd_parser.parse_top_section(_top_output(30))

        self.assertEqual(result["tasks"]["total"], "149")
        self.assertEqual(result["uptime"]["seconds"], 540)
        self.assertNotEqual(result["ram"], {})

    def test_asd_absent_leaves_process_empty(self):
        lines = [TOP_HEADER]
        lines.extend(_idle_kernel_threads(40))
        result = sys_cmd_parser.parse_top_section("\n".join(lines))

        self.assertEqual(result["asd_process"], {})

    def test_first_asd_line_wins(self):
        second_asd = ASD_LINE.replace("0.049t", "0.010t")
        output = "\n".join([_top_output(30), second_asd])
        result = sys_cmd_parser.parse_top_section(output)

        self.assertEqual(result["asd_process"]["resident_memory"], 53876069761)


if __name__ == "__main__":
    unittest.main()
