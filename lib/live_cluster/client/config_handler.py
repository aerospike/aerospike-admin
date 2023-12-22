# Copyright 2021-2023 Aerospike, Inc.
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

from os import path
import pkgutil
import json
import logging
import re

from lib.utils import version

logger = logging.getLogger(__name__)


class BaseConfigType:
    def __init__(self, dynamic, default):
        self.default = default
        self.dynamic = dynamic

    def validate(value):
        # OVERRIDE
        raise NotImplementedError

    # For testing
    def __eq__(self, o):
        if not isinstance(o, BaseConfigType):
            return False

        return self.default == o.default and self.dynamic == o.dynamic


class IntConfigType(BaseConfigType):
    def __init__(self, min, max, dynamic, default=None):
        self.min = min
        self.max = max
        super().__init__(dynamic, default)

    def validate(self, value):
        if isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                return False

        if not isinstance(value, int):
            return False

        return self.min <= value and value <= self.max

    # For testing
    def __eq__(self, o):
        if not isinstance(o, IntConfigType):
            return False

        return self.min == o.min and self.max == o.max and super().__eq__(o)

    def __str__(self):
        return "Int(min: {}, max: {})".format(self.min, self.max)


class StringConfigType(BaseConfigType):
    def __init__(self, regex, dynamic, default=None):
        """
        enum: list(str) or None to indicate string can be any value
        """
        self.regex = regex

        super().__init__(dynamic, default)

    def validate(self, value):
        if not isinstance(value, str):
            return False

        if self.regex is None:
            return True

        pattern = re.compile(self.regex)
        match = pattern.match(value)
        return match is not None

    # For testing
    def __eq__(self, o):
        if not isinstance(o, StringConfigType):
            return False

        return self.regex == o.regex and super().__eq__(o)

    def __str__(self):
        return "String"


class EnumConfigType(BaseConfigType):
    def __init__(self, enum, dynamic, default=None):
        """
        enum: list(str) or None to indicate string can be any value
        """
        self.enum = set(enum)

        super().__init__(dynamic, default)

    def validate(self, value):
        if not isinstance(value, str):
            return False

        return value in self.enum

    # For testing
    def __eq__(self, o):
        if not isinstance(o, EnumConfigType):
            return False

        return self.enum == o.enum and super().__eq__(o)

    def __str__(self):
        return "Enum([{}])".format(", ".join(self.enum))


class BoolConfigType(BaseConfigType):
    def __init__(self, dynamic, default=None):
        super().__init__(dynamic, default)

    def validate(self, value):
        if isinstance(value, str):
            value = value.lower()

            if value in {"false", "true"}:
                return True

        if not isinstance(value, bool):
            return False

        return True

    # For testing
    def __eq__(self, o):
        if not isinstance(o, BoolConfigType):
            return False

        return super().__eq__(o)

    def __str__(self):
        return "Boolean"


def configTypeFactory(value):
    """
    value currently only supports objects returned from the json schemas.  In the future
    if new objects are added (say if the server returns the object) then this can be
    expanded to support those.

    example value in json schemas:
        {
          "type": "integer",
          "default": 2,
          "minimum": 0,
          "maximum": 2147483647,
          "description": "",
          "dynamic": true
        }
    """

    if "type" not in value and "enum" not in value:
        new_value = None
        if "oneOf" in value:
            for one in value["oneOf"]:
                # TODO: Support oneOf type and array types. Will require changes to
                # auto-complete and config generator
                if "type" in one:
                    new_value = one  # hack, works in the rare case we have seen so far
                    break

        if not new_value:
            raise ValueError(
                "ConfigTypeFactory does not support value: {}".format(value)
            )

        value = new_value

    default = None
    dynamic = value["dynamic"]
    type_ = value["type"] if "type" in value else None

    if "default" in value:
        default = value["default"]

    if "enum" in value:
        enum = value["enum"]

        # Hack since log accepts upper and lowercase
        if "info" in enum and "INFO" in enum:
            # Used dict instead of set to maintain order
            enum = list({s.lower(): 0 for s in enum}.keys())

        return EnumConfigType(enum, dynamic, default)
    elif type_ == "string":
        # TODO Add in regex where needed, it will need to be a bit hardcoded
        return StringConfigType(None, dynamic, default)
    elif type_ == "integer":
        return IntConfigType(value["minimum"], value["maximum"], dynamic, default)
    elif type_ == "boolean":
        return BoolConfigType(dynamic, default)
    elif type_ == "array" and "items" in value:
        if "type" in value["items"] and value["items"]["type"] == "string":
            return StringConfigType(None, dynamic, default)

    raise ValueError("ConfigTypeFactory does not support type: {}".format(type_))


class BaseConfigHandler:
    def __init__(self, as_build):
        self.as_build = as_build

    def get_subcontext(self, context):
        """
        context: list(str) string of context to get subcontext.  List type for future
                 expansion
        Returns: list(str) of possible subcontext for the "context" given.
        Ex: (['namespace']) -> ['storage-engine','geo2dsphere-within','index-type', ...]
        """
        # OVERIDE
        raise NotImplementedError

    def get_params(self, context, dynamic=True):
        """
        context: list(str) each string is a subcontext of precedeing string.
        dynamic: True, filter params by dynamic.
        Returns: list(str) of parameters for the given context.
        Ex: (['namespace']) -> ['allow-ttl-without-nsup','background-scan-max-rps', ...]
        """
        # OVERIDE
        raise NotImplementedError

    def get_types(self, context, param) -> dict[str, BaseConfigType]:
        """
        context: list(str) each string is a subcontext of preceding string.
        param: list(str) parameters in the given context.
        Returns: dict{str: BaseConfigType()} of parameters for the given context. If a given
                 parameter does not exist None is returned for that parameter.
        Ex: (['namespace', 'storage-engine'], ['allow-ttl-without-nsup']) ->
            {'allow-ttl-without-nsup': BoolConfigType()}
        """
        # OVERIDE
        raise NotImplementedError


class JsonDynamicConfigHandler(BaseConfigHandler):
    # Some names in the config are wrong
    _param_replace_in = {
        "ignore-bin": "ignore-bins",
        "ignore-set": "ignore-sets",
        "ship-bin": "ship-bins",
        "ship-set": "ship-sets",
    }

    _context_replace_in = {
        "namespace": "namespaces",
        "set": "sets",
        "dc": "dcs",
    }

    def __init__(self, dir: str, as_build: str, strict=False):
        """_summary_

        Arguments:
            dir {str} -- Directory of config schema json files.
            as_build {str} -- Aerospike build version.

        Keyword Arguments:
            strict {bool} -- Controls whether an exception should be thrown in the even
            that a config schema can not be found for this build version. Otherwise,
            make a best effort by using the first preceding version (default: {False})
        """
        self.init_successful = False
        self.as_build = as_build
        super().__init__(as_build)

        try:
            as_build = ".".join(as_build.split(".")[0:3])
        except IndexError:
            logger.debug("JsonConfigHandler: Incorrect format for server version.")
            return

        try:
            file_map_path = path.join(dir, "schema_map.json")
            file_map_json = pkgutil.get_data(__name__, file_map_path)
        except Exception as e:
            logger.debug("%s", e)
            return

        try:
            file_map = json.loads(file_map_json)
        except Exception as e:
            logger.debug("JsonConfigHandler: Failed to load json: %s", e)
            return

        file_path = self._get_file_path(dir, as_build, file_map, strict)

        if file_path is None:
            return

        try:
            data = pkgutil.get_data(__name__, file_path)
        except Exception as e:
            logger.debug("%s", e)
            return

        try:
            config_schema = json.loads(data)
        except Exception as e:
            logger.debug("JsonConfigHandler: Failed to load json: %s", e)
            return

        self.schema = config_schema
        self.init_successful = True

    def _get_file_path(self, dir, as_build, file_map, strict: bool):
        # If the build provided is before the lowest supported version (LSV) use LSV
        file = list(file_map.values())[0]
        used_key = list(file_map.keys())[0]

        # Find the closest version to the one provided.
        for key in file_map:
            if version.LooseVersion(key) > version.LooseVersion(as_build):
                break

            file = file_map[key]
            used_key = key

        if (
            used_key
            and strict
            and version.LooseVersion(used_key) != version.LooseVersion(as_build)
        ):
            raise FileNotFoundError(
                f"No configuration schema found for Aerospike server {as_build}. Consider upgrading asadm."
            )

        logger.debug("JsonConfigHandler: Using server config schema %s", file)

        file_path = path.join(dir, file)

        return file_path

    def _replace_context_in(self, contexts):
        return self._replace_list(contexts, self._context_replace_in)

    def _replace_context_out(self, contexts):
        map = {v: k for k, v in self._context_replace_in.items()}
        return self._replace_list(contexts, map)

    def _replace_params_in(self, params):
        return self._replace_list(params, self._param_replace_in)

    def _replace_params_out(self, contexts):
        map = {v: k for k, v in self._param_replace_in.items()}
        return self._replace_list(contexts, map)

    def _replace_list(self, lst, map):
        return [map.get(item, item) for item in lst]

    def _unpack_properties(self, object_):
        """
        Takes the object and find all the keys we care about like subcontexts or
        config parameters.
        """
        if "oneOf" in object_ and "type" not in object_:
            result = {}
            for one in object_["oneOf"]:
                result.update(self._unpack_properties(one))

            return result

        if object_["type"] == "object":
            object_ = object_["properties"]
        elif object_["type"] == "array":
            object_ = object_["items"]["properties"]

        return object_

    def _get_objects(self, object_, context):
        if not context:
            return object_

        next_context = context.pop(0)

        """
        The json files have namespace replaced with namespaces and set with sets and
        dcs with dc. This is because they were created by the operator team and are user
        differently.
        """
        next_context = self._replace_context_in([next_context])[0]

        logger.debug(
            "JsonConfigHandler: Looking up next context %s in keys %s",
            next_context,
            object_.keys(),
        )

        if next_context not in object_:
            logger.debug(
                "JsonConfigHandler: Cant find context {} in keys {}".format(
                    next_context, object_.keys()
                )
            )
            return {}

        object_ = object_[next_context]

        properties = self._unpack_properties(object_)

        return self._get_objects(properties, context)

    def get_subcontext(self, context):
        if not self.init_successful:
            return []

        if isinstance(context, str):
            context = [context]

        top_level_contexts = self.schema["properties"]

        try:
            param_objects = self._get_objects(top_level_contexts, context)
        except Exception as e:
            logger.debug(
                "JsonConfigHandler: Failed to find objects and context {}, {}".format(
                    context, e
                )
            )
            return []

        filtered_keys = [
            key
            for key, value in param_objects.items()
            if (
                (
                    "type" in value
                    and (
                        value["type"] == "object"
                        or (
                            value["type"] == "array"
                            and value["items"]["type"] == "object"
                        )
                    )
                )
                or ("oneOf" in value)
            )
        ]

        logger.debug(
            "JsonConfigHandler: unwanted-keys: {}".format(
                set(param_objects.keys()) - set(filtered_keys)
            )
        )

        return self._replace_context_out(filtered_keys)

    def get_params(self, context, dynamic=True):
        if not self.init_successful:
            return []

        if isinstance(context, str):
            context = [context]

        top_level_contexts = self.schema["properties"]

        try:
            param_objects = self._get_objects(top_level_contexts, context)
        except Exception as e:
            logger.debug(
                "JsonConfigHandler: Failed to find objects and context {}, {}".format(
                    context, e
                )
            )
            return []

        filtered_keys = [
            key
            for key, value in param_objects.items()
            if (not dynamic or ("dynamic" in value and value["dynamic"] is True))
        ]

        logger.debug(
            "JsonConfigHandler: unwanted-keys: {}".format(
                set(param_objects.keys()) - set(filtered_keys)
            )
        )

        # Naming convention in json files does 100% match actual config names
        return self._replace_params_out(filtered_keys)

    def get_types(self, context, params):
        if not self.init_successful:
            return {}

        if isinstance(context, str):
            context = [context]

        if isinstance(params, str):
            params = [params]

        top_level_contexts = self.schema["properties"]
        objects = self._get_objects(top_level_contexts, context)
        result = {}

        internal_params = self._replace_params_in(params[:])

        for param, internal_param in zip(params, internal_params):
            if internal_param in objects:
                value = objects[internal_param]
                try:
                    result[param] = configTypeFactory(value)
                except KeyError as e:
                    logger.debug(
                        f"Failed to create config type for param {param} in context {context}, {e}"
                    )
                    result[param] = None
            else:
                result[param] = None

        return result
