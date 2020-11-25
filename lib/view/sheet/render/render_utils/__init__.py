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


class Aggregator(object):
    def __init__(self, aggregator, values):
        self.decleration = aggregator
        self.initialized = False
        self.result = None

        for value in values:
            self.update(value)

    def update(self, value):
        if value is None:
            return

        if not self.initialized:
            self.initialized = True

            if self.decleration.initializer is None:
                self.result = value
                return

            self.result = self.decleration.initializer

        self.result = self.decleration.func(self.result, value)


class ErrorEntry(object):
    pass


class NoEntry(object):
    def __lt__(self,other):
        return (False)

    def __le__(self,other):
        return(True)

    def __gt__(self,other):
        return(True)

    def __ge__(self,other):
        return(False)


ErrorEntry = ErrorEntry()
NoEntry = NoEntry()
