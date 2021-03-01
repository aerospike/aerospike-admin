# Copyright 2019 Aerospike, Inc.
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


def source_hierarchy(source_path):
    return source_path.split(".")


def source_root(source_path):
    return source_hierarchy(source_path)[0]


def source_lookup(sources, source_path):
    cur_node = sources

    for node in source_hierarchy(source_path):
        cur_node = cur_node[node]

    return cur_node
