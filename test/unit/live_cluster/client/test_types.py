# Copyright 2021-2025 Aerospike, Inc.
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
from lib.live_cluster.client.config_handler import BoolConfigType, IntConfigType
from mock import MagicMock
import unittest

from parameterized import parameterized

from test.unit import util
from lib.live_cluster.client.node import (
    ASInfoConfigError,
    ASInfoResponseError,
    ASResponse,
)


class ASInfoErrorTest(unittest.TestCase):
    def test_raises_exception_with_ok(self):
        util.assert_exception(
            self,
            ValueError,
            'info() returned value "ok" which is not an error.',
            ASInfoResponseError,
            "message",
            "ok",
        )

        util.assert_exception(
            self,
            ValueError,
            'info() returned value "ok" which is not an error.',
            ASInfoResponseError,
            "message",
            "OK",
        )

        util.assert_exception(
            self,
            ValueError,
            'info() returned value "ok" which is not an error.',
            ASInfoResponseError,
            "message",
            "",
        )

    def test_creates_str(self):
        message = "test message"
        responses = [
            "error=a-white-whale",
            "ERROR=a-white-whale.",
            "ERROR:1234:a-white-whale",
            "ERROR::a-white-whale",
            "error:1234:a-white-whale.",
            "error::a-white-whale",
            "fail:1234:a-white-whale.",
            "FAIL::a-white-whale",
            "error:1234:a-white-whale.",
            "error::a-white-whale",
        ]
        exp_string = "test message : a-white-whale."

        for response in responses:
            error = ASInfoResponseError(message, response)
            self.assertEqual(
                str(error), exp_string, "Fail caused by {}".format(response)
            )

    def test_create_unknow_error_str(self):
        message = "test message"
        responses = [
            "error",
            "ERROR",
            "fail",
            "FAIL",
        ]
        exp_string = "test message : Unknown error occurred."

        for response in responses:
            error = ASInfoResponseError(message, response)
            self.assertEqual(
                str(error), exp_string, "Fail caused by {}".format(response)
            )


class ASInfoConfigErrorTest(unittest.TestCase):
    def setUp(self):
        self.node_mock = MagicMock()
        self.test_message = "this is a test message"

    def test_invalid_subcontext(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        expected = "this is a test message : Invalid subcontext bar4."

        actual = ASInfoConfigError(
            self.test_message,
            "irrelevant",
            self.node_mock,
            ["foo2", "blah1", "bar4"],
            "irrelevant",
            "irrelevant",
        )

        self.assertEqual(str(actual), expected)

    def test_invalid_param(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = None
        expected = "this is a test message : Invalid parameter."

        actual = ASInfoConfigError(
            self.test_message,
            "ok",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "bad-param",
            "irrelevant",
        )

        self.assertEqual(str(actual), expected)

    def test_param_is_not_dynamic(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = BoolConfigType(False)
        expected = "this is a test message : Parameter is not dynamically configurable."

        actual = ASInfoConfigError(
            self.test_message,
            "ok",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "bad-param",
            "irrelevant",
        )

        self.assertEqual(str(actual), expected)

    def test_invalid_value(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = IntConfigType(
            0,
            10,
            True,
        )
        expected = "this is a test message : Invalid value for Int(min: 0, max: 10)."

        actual = ASInfoConfigError(
            self.test_message,
            "ok",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "good-param",
            -2,
        )

        self.assertEqual(str(actual), expected)

    def test_unknown_error(self):
        """
        This is when the server sends back ambiguous error message but a problem could not
        be found with context, param, or value.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = IntConfigType(
            0,
            10,
            True,
        )
        expected = "this is a test message : this-is-the-reason."

        actual = ASInfoConfigError(
            self.test_message,
            "error::this-is-the-reason",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "good-param",
            5,
        )

        self.assertEqual(str(actual), expected)

    def test_error_with_message(self):
        """
        This is when the server sends back error message with a reason AND a problem
        could not be found with context, param, or value.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = IntConfigType(
            0,
            10,
            True,
        )
        expected = "this is a test message : Unknown error occurred."

        actual = ASInfoConfigError(
            self.test_message,
            "error",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "good-param",
            5,
        )

        self.assertEqual(str(actual), expected)

    def test_role_violation_error_takes_precedence(self):
        """
        Test that role violation errors are shown instead of validation errors.
        This tests the fix for the issue where role violations were incorrectly
        displayed as "Parameter is not dynamically configurable".
        """
        self.node_mock.config_subcontext.side_effect = [
            ["namespace"],
        ]
        # Configure a non-dynamic parameter to trigger the old behavior
        self.node_mock.config_type.return_value = BoolConfigType(False)  # non-dynamic

        # Server response indicates role violation
        role_violation_resp = (
            "ERROR:81:role violation - requires permission 'set-config'"
        )
        expected = "this is a test message : role violation - requires permission 'set-config'."

        actual = ASInfoConfigError(
            self.test_message,
            role_violation_resp,
            self.node_mock,
            ["namespace"],
            "replication-factor",
            "2",
        )

        # Should show the role violation error, not "Parameter is not dynamically configurable"
        self.assertEqual(str(actual), expected)

    def test_authentication_error_takes_precedence(self):
        """
        Test that authentication errors are shown instead of validation errors.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["service"],
        ]
        # Configure an invalid parameter to trigger validation error
        self.node_mock.config_type.return_value = None

        # Server response indicates authentication failure
        auth_error_resp = "ERROR:80:authentication failed"
        expected = "this is a test message : authentication failed."

        actual = ASInfoConfigError(
            self.test_message,
            auth_error_resp,
            self.node_mock,
            ["service"],
            "bad-param",
            "some-value",
        )

        # Should show the authentication error, not "Invalid parameter"
        self.assertEqual(str(actual), expected)

    def test_permission_denied_error_takes_precedence(self):
        """
        Test that permission denied errors are shown instead of validation errors.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["security"],
        ]
        # Configure an invalid value to trigger validation error
        self.node_mock.config_type.return_value = IntConfigType(0, 10, True)

        # Server response indicates permission denied
        permission_error_resp = "ERROR:82:permission denied"
        expected = "this is a test message : permission denied."

        actual = ASInfoConfigError(
            self.test_message,
            permission_error_resp,
            self.node_mock,
            ["security"],
            "good-param",
            -5,  # Invalid value
        )

        # Should show the permission error, not "Invalid value for Int(min: 0, max: 10)"
        self.assertEqual(str(actual), expected)

    def test_server_error_with_different_format_takes_precedence(self):
        """
        Test that server errors with different formats are handled correctly.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["network"],
        ]
        # Configure a non-dynamic parameter
        self.node_mock.config_type.return_value = BoolConfigType(False)

        # Server response with different error format
        server_error_resp = "FAIL:100:cluster unstable"
        expected = "this is a test message : cluster unstable."

        actual = ASInfoConfigError(
            self.test_message,
            server_error_resp,
            self.node_mock,
            ["network"],
            "some-param",
            "some-value",
        )

        # Should show the server error, not validation error
        self.assertEqual(str(actual), expected)

    def test_validation_errors_still_work_when_no_server_error(self):
        """
        Test that validation errors still work normally when there's no server error.
        This ensures backward compatibility.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["namespace"],
        ]
        # Configure a non-dynamic parameter
        self.node_mock.config_type.return_value = BoolConfigType(False)

        # No meaningful server response (like "ok" or empty)
        ok_resp = "ok"
        expected = "this is a test message : Parameter is not dynamically configurable."

        actual = ASInfoConfigError(
            self.test_message,
            ok_resp,
            self.node_mock,
            ["namespace"],
            "some-param",
            "some-value",
        )

        # Should fall back to validation error as before
        self.assertEqual(str(actual), expected)

    def test_empty_response_falls_back_to_validation(self):
        """
        Test that empty responses fall back to validation errors.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["service"],
        ]
        self.node_mock.config_type.return_value = None

        # Empty server response
        empty_resp = ""
        expected = "this is a test message : Invalid parameter."

        actual = ASInfoConfigError(
            self.test_message,
            empty_resp,
            self.node_mock,
            ["service"],
            "bad-param",
            "some-value",
        )

        # Should fall back to validation error
        self.assertEqual(str(actual), expected)


class ASResponseTest(unittest.TestCase):
    @parameterized.expand(
        [
            (0, "Ok"),
            (94, "Error querying ldap server"),
            (99999, "Error response code (99999)"),
        ]
    )
    def test_success(self, code, expected):
        self.assertEqual(str(ASResponse(code)), expected)

    def test_fail(self):
        self.assertRaises(ValueError, ASResponse, "wrong")
