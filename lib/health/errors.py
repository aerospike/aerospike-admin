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


class Errors:
    errors = {
        "HEALTH_ERROR1": "System Has Low Memory Pct",
        "HEALTH_ERROR2": "System Has Low Memory Pct",
        "HEALTH_ERROR3": "System lot of connection Churn",
        "HEALTH_ERROR4": "Misconfigured Namespace memory sizes",
        "HEALTH_ERROR5": "Namespace Low In Disk Avail PCT",
        "HEALTH_ERROR6": "Namespace Possible misconfiguration",
        "HEALTH_ERROR7": "Namespace Anamolistic Pattern",
        "HEALTH_ERROR8": "Set Delete in progress",
    }

    @staticmethod
    def get_error_discription(e_id):
        if e_id in Errors.errors:
            return Errors.errors[e_id]
        return e_id
