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

# Test modules that terminate a node rather than just reading from one. They run
# last: 'manage checkpoint save' departs the node it targets, and even with a clean
# per-test stop()/start() the next module has come up with a strong-consistency
# roster that still named the departed node ("Node not found for partition
# test_sc:<pid>"). Nothing may depend on cluster state after these run.
DESTRUCTIVE_MODULES = ("test_checkpoint.py",)


def pytest_collection_modifyitems(items):
    def is_destructive(item):
        module_path = item.nodeid.split("::")[0]

        return module_path.endswith(DESTRUCTIVE_MODULES)

    # Stable, so everything keeps its relative order and only these move to the end.
    items.sort(key=is_destructive)
