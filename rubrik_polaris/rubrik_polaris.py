# Copyright 2020 Rubrik, Inc.
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.

import logging
import os
import urllib3
from .exceptions import InvalidParameterException
import pprint
import inspect


class PolarisClient:
    # Public
    from .lib.common.polaris import get_sla_domains, submit_on_demand, submit_assign_sla, get_task_status
    from .lib.compute import get_instances_azure, get_instances_ec2, get_instances_gce
    from .lib.accounts import get_accounts_aws, get_accounts_azure, get_accounts_gcp, delete_account_aws
    from .lib.accounts import add_account_aws, get_accounts_aws_detail, get_account_aws_native_id
    from .lib.compute import get_object_ids_azure, get_object_ids_ec2, get_object_ids_gce

    # Private
    from .lib.common.connection import _query, _get_access_token
    from .lib.common.graphql import _dump_nodes, _get_query_names_from_graphql_query
    from .lib.accounts import _invoke_account_delete_aws, _invoke_aws_stack, _commit_account_delete_aws
    from .lib.accounts import _destroy_aws_stack, _disable_account_aws

    def __init__(self, _domain, _username, _password, enable_logging=False, logging_level="debug", **kwargs):
        from .lib.common.graphql import _build_graphql_maps

        self._pp = pprint.PrettyPrinter(indent=4)

        # Enable logging for the SDK
        valid_logging_levels = {
            "debug": logging.DEBUG,
            "critical": logging.CRITICAL,
            "error": logging.ERROR,
            "warning": logging.WARNING,
            "info": logging.INFO,
        }
        if logging_level not in valid_logging_levels:
            raise InvalidParameterException(
                "'{}' is not a valid logging_level. Valid choices are 'debug', 'critical', 'error', 'warning', "
                "or 'info'.".format(
                    logging_level))
        self.logging_level = logging_level
        if enable_logging:
            logging.getLogger().setLevel(valid_logging_levels[self.logging_level])

        # Set base variables
        self._kwargs = kwargs
        self._domain = _domain
        self._username = _username
        self._password = _password
        self._module_path = os.path.dirname(os.path.realpath(__file__))
        self._data_path = "{}/graphql/".format(self.module_path)
        self._log("Polaris Domain: {}".format(self._domain))

        # Switch off SSL checks if needed
        if 'insecure' in self._kwargs and self._kwargs['insecure']:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Adjust Polaris domain if a custom root is defined
        if 'root_domain' in self._kwargs and self._kwargs['root_domain'] is not None:
            self._baseurl = "https://{}.{}/api/graphql".format(self._domain, self._kwargs['root_domain'])
        else:
            self._baseurl = "https://{}.my.rubrik.com/api/graphql".format(self._domain)

        # Get Auth Token and assemble header
        self._access_token = self._get_access_token()
        del(self._username, self._password)
        self._headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + self._access_token
        }

        # Get graphql content
        (self._graphql_query, self._graphql_mutation, self._graphql_file_type_map) = _build_graphql_maps(self)

    def _log(self, log_message):
        """Create properly formatted debug log messages.

        Arguments:
            log_message {str} -- The message to pass to the debug log.
        """
        log = logging.getLogger(__name__)
        set_logging = {
            "debug": log.debug,
            "critical": log.critical,
            "error": log.error,
            "warning": log.warning,
            "info": log.info

        }
        set_logging[self.logging_level](log_message)
