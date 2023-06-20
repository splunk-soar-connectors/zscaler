# File: zscaler_connector.py
#
# Copyright (c) 2017-2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import json
import re
import time

import phantom.app as phantom
import phantom.rules as phantom_rules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from zscaler_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class ZscalerConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ZscalerConnector, self).__init__()
        self._state = None
        self._base_url = None
        self._response = None  # The most recent response object
        self._headers = None
        self._category = None
        self._retry_rest_call = None  # Retry rest call when get status_code 409 or 429

    def _get_err_msg_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        err_code = None
        err_msg = ZSCALER_ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    err_code = e.args[0]
                    err_msg = e.args[1]
                elif len(e.args) == 1:
                    err_msg = e.args[0]
        except Exception as e:
            self.debug_print("Error occurred while getting message from response. Error : {}".format(e))

        if not err_code:
            err_text = "Error Message: {}".format(err_msg)
        else:
            err_text = "Error Code: {}. Error Message: {}".format(err_code, err_msg)

        return err_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, ZSCALER_VALID_INTEGER_MSG.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, ZSCALER_VALID_INTEGER_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, ZSCALER_NON_NEGATIVE_INTEGER_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, ZSCALER_POSITIVE_INTEGER_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            err_text = soup.text
            split_lines = err_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            err_text = '\n'.join(split_lines)
        except Exception as e:
            err_text = "Cannot parse err details"
            self.debug_print("{}. Error: {}".format(err_text, e))

        err_text = err_text

        msg = "Please check the asset configuration parameters (the base_url should not end with "\
            "/api/v1 e.g. https://admin.zscaler_instance.net)."

        if len(err_text) <= 500:
            msg += "Status Code: {0}. Data from server:\n{1}\n".format(status_code, err_text)

        msg = msg.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}"
                .format(self._get_err_msg_from_exception(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        try:
            msg = resp_json['message']
        except Exception:
            msg = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}')
            )
        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        msg = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            try:
                ipaddress.ip_address(unicode(ip_address_input))
            except NameError:
                ipaddress.ip_address(str(ip_address_input))
        except Exception:
            return False

        return True

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", use_json=True, timeout_flag=0):

        resp_json = None

        if headers is None:
            headers = {}

        if self.get_action_identifier() != 'submit_file':
            headers.update(self._headers)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        req_timeout = ZSCALER_DEFAULT_TIMEOUT

        if timeout_flag == 1:
            req_timeout = None

        # Create a URL to connect to
        url = '{}{}'.format(self._base_url, endpoint)
        try:
            if use_json:
                r = request_func(
                    url,
                    json=data,
                    headers=headers,
                    params=params,
                    timeout=req_timeout
                )
            else:
                r = request_func(
                    url,
                    data=data,
                    headers=headers,
                    params=params,
                    timeout=req_timeout
                )
        except Exception as e:
            error_message = self._get_err_msg_from_exception(e)
            error_message = re.sub(ZSCALER_MATCH_REGEX, ZSCALER_REPLACE_REGEX, error_message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to Zscaler server. {}"
                                                   .format(error_message)), resp_json)

        self._response = r

        return self._process_response(r, action_result)

    def _parse_retry_time(self, retry_time):
        # Instead of just giving a second value, "retry-time" will return a string like "0 seconds"
        # I don't know if the second unit can be not seconds
        parts = retry_time.split()
        if parts[1].lower() == "seconds":
            return int(parts[0])
        if parts[1].lower() == "minutes":
            return int(parts[0]) * 60
        else:
            return None

    def _make_rest_call_helper(self, *args, **kwargs):
        # There are two rate limits
        #  1. There is a maximum limit of requests per second, depending on if its a GET / POST / PUT / DELETE
        #  2. There is a maximum number of requests per hour
        # Regardless, the response will include a try-after value, which we can use to sleep
        ret_val, response = self._make_rest_call(*args, **kwargs)
        if phantom.is_fail(ret_val):
            if self._response is None:
                return ret_val, response
            if self._response.status_code == 409 and self._retry_rest_call:  # Lock not available
                # This basically just means we need to try again
                self.debug_print("Error 409: Lock not available")
                self.send_progress("Error 409: Lock not available: Retrying in 1 second")
                time.sleep(1)
                self._retry_rest_call = False  # make it to false to avoid extra rest call
                return self._make_rest_call_helper(*args, **kwargs)
            if self._response.status_code == 429 and self._retry_rest_call:  # Rate limit exceeded
                try:
                    retry_time = self._response.json()['Retry-After']
                except KeyError:
                    self.debug_print("KeyError")
                    return ret_val, response
                self.debug_print("Retry Time: {}".format(retry_time))
                seconds_to_wait = self._parse_retry_time(retry_time)
                if seconds_to_wait is None or seconds_to_wait < 0:
                    return retry_time, response
                self.send_progress("Exceeded rate limit: Retrying after {}".format(retry_time))
                time.sleep(seconds_to_wait)
                self._retry_rest_call = False  # make it to false to avoid extra rest call
                return self._make_rest_call_helper(*args, **kwargs)
        return ret_val, response

    def _obfuscate_api_key(self, api_key):
        now = str(int(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(n), 1):
            key += api_key[int(n[i])]
        for j in range(0, len(r), 1):
            key += api_key[int(r[j]) + 2]

        return now, key

    def _init_session(self):
        username = self._username
        password = self._password
        api_key = self._api_key
        try:
            timestamp, obf_api_key = self._obfuscate_api_key(api_key)
        except Exception:
            return self.set_status(
                phantom.APP_ERROR,
                "Error obfuscating API key"
            )

        body = {
            'apiKey': obf_api_key,
            'username': username,
            'password': password,
            'timestamp': timestamp
        }

        action_result = ActionResult()
        ret_val, response = self._make_rest_call_helper(
            '/api/v1/authenticatedSession',
            action_result, data=body,
            method='post'
        )
        if phantom.is_fail(ret_val):
            self.debug_print('Error starting Zscaler session: {}'.format(action_result.get_message()))
            return self.set_status(
                phantom.APP_ERROR,
                'Error starting Zscaler session: {}'.format(action_result.get_message())
            )
        else:
            self.save_progress('Successfully started Zscaler session')
            self._headers = {
                'cookie': self._response.headers['Set-Cookie'].split(';')[0].strip()
            }
            return phantom.APP_SUCCESS

    def _deinit_session(self):
        action_result = ActionResult()
        config = self.get_config()
        self._base_url = config['base_url'].rstrip('/')
        ret_val, response = self._make_rest_call_helper('/api/v1/authenticatedSession', action_result, method='delete')

        if phantom.is_fail(ret_val):
            self.debug_print("Deleting the authenticated session failed on the ZScaler server.")
            self.debug_print("Marking the action as successful run.")

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        # If we are here we have successfully initialized a session
        self.save_progress("Test Connectivity Passed")
        self.debug_print("Test Connectivity Passed.")
        return self.set_status(phantom.APP_SUCCESS)

    def _filter_endpoints(self, action_result, to_add, existing, action, name):
        if action == "REMOVE_FROM_LIST":
            msg = "{} contains none of these endpoints".format(name)
            endpoints = list(set(existing) - (set(existing) - set(to_add)))
        else:
            msg = "{} contains all of these endpoints".format(name)
            endpoints = list(set(to_add) - set(existing))

        if not endpoints:
            summary = action_result.set_summary({})
            summary['updated'] = []
            summary['ignored'] = to_add
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, msg), None)
        return RetVal(phantom.APP_SUCCESS, endpoints)

    def _get_blocklist(self, action_result):
        return self._make_rest_call_helper('/api/v1/security/advanced', action_result)

    def _check_blocklist(self, action_result, endpoints, action):
        ret_val, response = self._get_blocklist(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(ret_val, None)

        blocklist = response.get('blacklistUrls', [])

        return self._filter_endpoints(action_result, endpoints, blocklist, action, 'Blocklist')

    def _amend_blocklist(self, action_result, endpoints, action):
        ret_val, filtered_endpoints = self._check_blocklist(action_result, endpoints, action)
        if phantom.is_fail(ret_val) or filtered_endpoints is None:
            return ret_val

        params = {'action': action}
        data = {
            "blacklistUrls": filtered_endpoints
        }
        ret_val, response = self._make_rest_call_helper(
            '/api/v1/security/advanced/blacklistUrls', action_result, params=params,
            data=data, method="post"
        )
        if phantom.is_fail(ret_val) and self._response.status_code != 204:
            return ret_val
        summary = action_result.set_summary({})
        summary['updated'] = filtered_endpoints
        summary['ignored'] = list(set(endpoints) - set(filtered_endpoints))
        # Encode the unicode IP or URL strings
        summary['updated'] = [element for element in summary['updated']]
        summary['ignored'] = [element for element in summary['ignored']]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_allowlist(self, action_result):
        return self._make_rest_call_helper('/api/v1/security', action_result)

    def _check_allowlist(self, action_result, endpoints, action):
        ret_val, response = self._get_allowlist(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(ret_val, None)

        allowlist = response.get('whitelistUrls', [])
        self._allowlist = allowlist

        return self._filter_endpoints(action_result, endpoints, allowlist, action, 'Allowlist')

    def _amend_allowlist(self, action_result, endpoints, action):
        ret_val, filtered_endpoints = self._check_allowlist(action_result, endpoints, action)
        if phantom.is_fail(ret_val) or filtered_endpoints is None:
            return ret_val

        if action == "ADD_TO_LIST":
            to_add_endpoints = list(set(self._allowlist + filtered_endpoints))
        else:
            to_add_endpoints = list(set(self._allowlist) - set(filtered_endpoints))

        data = {
            "whitelistUrls": to_add_endpoints
        }
        ret_val, response = self._make_rest_call_helper(
            '/api/v1/security', action_result,
            data=data, method='put'
        )
        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        summary = action_result.set_summary({})
        summary['updated'] = filtered_endpoints
        summary['ignored'] = list(set(endpoints) - set(filtered_endpoints))
        # Encode the unicode IP or URL strings
        summary['updated'] = [element for element in summary['updated']]
        summary['ignored'] = [element for element in summary['ignored']]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_category(self, action_result, category):
        ret_val, response = self._make_rest_call_helper('/api/v1/urlCategories', action_result)
        if phantom.is_fail(ret_val):
            return ret_val, response

        for cat in response:
            if cat.get('configuredName', None) == category:
                return RetVal(phantom.APP_SUCCESS, cat)

        for cat in response:
            if cat['id'] == category:
                return RetVal(phantom.APP_SUCCESS, cat)

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Unable to find category"
            ),
            None
        )

    def _check_category(self, action_result, endpoints, category, action):
        ret_val, response = self._get_category(action_result, category)
        if phantom.is_fail(ret_val):
            return ret_val, response

        self._category = response
        urls = response.get('dbCategorizedUrls', [])

        return self._filter_endpoints(action_result, endpoints, urls, action, 'Category')

    def _amend_category(self, action_result, endpoints, category, action):
        ret_val, filtered_endpoints = self._check_category(action_result, endpoints, category, action)
        if phantom.is_fail(ret_val) or filtered_endpoints is None:
            return ret_val

        params = {'action': action }

        data = {
            "configuredName": self._category.get('configuredName'),
            "keywordsRetainingParentCategory": self._category.get("keywordsRetainingParentCategory", []),
            "urls": [],
            "dbCategorizedUrls": filtered_endpoints
        }

        ret_val, response = self._make_rest_call_helper(
            '/api/v1/urlCategories/{}'.format(self._category['id']),
            action_result, data=data, method='put', params=params, timeout_flag=1
        )
        if phantom.is_fail(ret_val):
            return ret_val
        action_result.add_data(response)
        summary = action_result.set_summary({})
        summary['updated'] = filtered_endpoints
        summary['ignored'] = list(set(endpoints) - set(filtered_endpoints))
        # Encode the unicode IP or URL strings
        summary['updated'] = [element for element in summary['updated']]
        summary['ignored'] = [element for element in summary['ignored']]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _block_endpoint(self, action_result, endpoints, category):
        list_endpoints = list()
        list_endpoints = [x.strip() for x in endpoints.split(',')]
        endpoints = list(filter(None, list_endpoints))
        endpoints = self._truncate_protocol(endpoints)

        if self.get_action_identifier() in ['block_url']:
            ret_val = self._check_for_overlength(action_result, endpoints)
            if phantom.is_fail(ret_val):
                return ret_val

        if category is None:
            return self._amend_blocklist(action_result, endpoints, 'ADD_TO_LIST')
        else:
            return self._amend_category(action_result, endpoints, category, 'ADD_TO_LIST')

    def _unblock_endpoint(self, action_result, endpoints, category):
        list_endpoints = list()
        list_endpoints = [x.strip() for x in endpoints.split(',')]
        endpoints = list(filter(None, list_endpoints))
        endpoints = self._truncate_protocol(endpoints)

        if self.get_action_identifier() in ['unblock_url']:
            ret_val = self._check_for_overlength(action_result, endpoints)
            if phantom.is_fail(ret_val):
                return ret_val

        if category is None:
            return self._amend_blocklist(action_result, endpoints, 'REMOVE_FROM_LIST')
        else:
            return self._amend_category(action_result, endpoints, category, 'REMOVE_FROM_LIST')

    def _handle_block_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._block_endpoint(action_result, param['ip'], param.get('url_category'))

    def _handle_block_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._block_endpoint(action_result, param['url'], param.get('url_category'))

    def _handle_unblock_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._unblock_endpoint(action_result, param['ip'], param.get('url_category'))

    def _handle_unblock_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._unblock_endpoint(action_result, param['url'], param.get('url_category'))

    def _allowlist_endpoint(self, action_result, endpoints, category):
        list_endpoints = list()
        list_endpoints = [x.strip() for x in endpoints.split(',')]
        endpoints = list(filter(None, list_endpoints))
        endpoints = self._truncate_protocol(endpoints)

        if self.get_action_identifier() in ['allow_url']:
            ret_val = self._check_for_overlength(action_result, endpoints)
            if phantom.is_fail(ret_val):
                return ret_val

        if category is None:
            return self._amend_allowlist(action_result, endpoints, 'ADD_TO_LIST')
        else:
            return self._amend_category(action_result, endpoints, category, 'ADD_TO_LIST')

    def _unallow_endpoint(self, action_result, endpoints, category):
        list_endpoints = list()
        list_endpoints = [x.strip() for x in endpoints.split(',')]
        endpoints = list(filter(None, list_endpoints))
        endpoints = self._truncate_protocol(endpoints)

        if self.get_action_identifier() in ['unallow_url']:
            ret_val = self._check_for_overlength(action_result, endpoints)
            if phantom.is_fail(ret_val):
                return ret_val

        if category is None:
            return self._amend_allowlist(action_result, endpoints, 'REMOVE_FROM_LIST')
        else:
            return self._amend_category(action_result, endpoints, category, 'REMOVE_FROM_LIST')

    def _handle_allow_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._allowlist_endpoint(action_result, param['ip'], param.get('url_category'))

    def _handle_allow_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._allowlist_endpoint(action_result, param['url'], param.get('url_category'))

    def _handle_unallow_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._unallow_endpoint(action_result, param['ip'], param.get('url_category'))

    def _handle_unallow_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._unallow_endpoint(action_result, param['url'], param.get('url_category'))

    def _lookup_endpoint(self, action_result, endpoints):

        if not endpoints:
            action_result.set_status(phantom.APP_ERROR, "Please provide valid list of URL(s)")

        ret_val, response = self._make_rest_call_helper(
            '/api/v1/urlLookup', action_result,
            data=endpoints, method='post'
        )
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, blocklist_response = self._make_rest_call_helper(
            '/api/v1/security/advanced', action_result, method='get'
        )

        if phantom.is_fail(ret_val):
            return ret_val

        for e in endpoints:
            if e in blocklist_response.get('blacklistUrls', []):
                [response[i].update({"blocklisted": True}) for i, item in enumerate(response) if item['url'] == e]
            else:
                [response[i].update({"blocklisted": False}) for i, item in enumerate(response) if item['url'] == e]

        action_result.update_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully completed lookup")

    def _handle_get_report(self, param):
        """
        This action is used to retrieve a sandbox report of provided md5 file hash
        :param file_hash: md5Hash of file
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param['file_hash']

        ret_val, sandbox_report = self._make_rest_call_helper('/api/v1/sandbox/report/{0}?details=full'
            .format(file_hash), action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if sandbox_report.get(ZSCALER_JSON_FULL_DETAILS) and ZSCLAER_ERR_MD5_UNKNOWN_MSG in sandbox_report.get(
                                                                        ZSCALER_JSON_FULL_DETAILS):
            return action_result.set_status(phantom.APP_ERROR, sandbox_report.get(ZSCALER_JSON_FULL_DETAILS))

        action_result.add_data(sandbox_report)

        return action_result.set_status(phantom.APP_SUCCESS, ZSCALER_SANDBOX_GET_REPORT_MSG)

    def _handle_submit_file(self, param):
        """
        This action is used to retrieve a sandbox report of provided md5 file hash
        :param file_hash: md5Hash of file
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not (self._sandbox_api_token and self._sandbox_base_url):
            return action_result.set_status(
                phantom.APP_ERROR, "Please provide ZScaler Sandbox Base URL and API token to submit the file to Sandbox")
        self._base_url = self._sandbox_base_url

        try:
            file_id = param['vault_id']
            success, msg, file_info = phantom_rules.vault_info(vault_id=file_id)
            file_info = list(file_info)[0]
        except IndexError:
            return action_result.set_status(phantom.APP_ERROR, 'Vault file could not be found with supplied Vault ID')
        except Exception as e:
            err_msg = self._get_err_msg_from_exception(e)
            self.debug_print("Vault ID not valid. Error: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, 'Vault ID not valid')

        params = {
            'force': 1 if param.get('force', False) else 0,
            'api_token': self._sandbox_api_token
        }

        with open(file_info.get('path'), 'rb') as f:
            data = f.read()

        ret_val, resp_json = self._make_rest_call_helper('/zscsb/submit',
            action_result, params=params, data=data, method='post', use_json=False)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_json.get('code') != 200:
            return action_result.set_status(phantom.APP_ERROR,
                "Status code: {} Details: {}. Please make sure ZScaler Sandbox Base URL and API token are configured correctly"
                .format(resp_json.get('code'), resp_json.get('message')))

        action_result.add_data(resp_json)

        if resp_json.get('message') == '/submit response OK':
            msg = ZSCALER_SANDBOX_SUBMIT_FILE_MSG
        else:
            if resp_json.get('message').lower() != resp_json.get('sandboxSubmission').lower():
                msg = 'Status Code: {}. Data from server: {}. {}.'.format(resp_json.get('code'), resp_json.get('sandboxSubmission'),
                    resp_json.get('message'))
            else:
                msg = 'Status Code: {}. Data from server: {}'.format(resp_json.get('code'), resp_json.get('message'))

        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_list_url_categories(self, param):
        """
        This action is used to fetch all the URL categories
        :param: No parameters
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, list_url_categories = self._make_rest_call_helper('/api/v1/urlCategories', action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for url_category in list_url_categories:
            action_result.add_data(url_category)

        summary = action_result.update_summary({})
        summary['total_url_categories'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_endpoints = list()
        list_endpoints = [x.strip() for x in param['ip'].split(',')]
        endpoints = list(filter(None, list_endpoints))

        return self._lookup_endpoint(action_result, endpoints)

    def _handle_lookup_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        list_endpoints = list()
        list_endpoints = [x.strip() for x in param['url'].split(',')]
        endpoints = list(filter(None, list_endpoints))

        endpoints = self._truncate_protocol(endpoints)
        ret_val = self._check_for_overlength(action_result, endpoints)

        if phantom.is_fail(ret_val):
            return ret_val

        return self._lookup_endpoint(action_result, endpoints)

    def _truncate_protocol(self, endpoints):
        """
        This function truncates the protocol from the list of URLs if present
        :param: endpoints: list of URLs
        :return: updated list of url
        """
        for i in range(len(endpoints)):
            if endpoints[i].startswith("http://"):
                endpoints[i] = endpoints[i][(len("http://")):]
            elif endpoints[i].startswith("https://"):
                endpoints[i] = endpoints[i][(len("https://")):]

        return endpoints

    def _check_for_overlength(self, action_result, endpoints):
        """This function checks whether the length of each url is not more
        than 1024
        :param: :endpoints: list of URLs
        """
        for url in endpoints:
            if len(url) > 1024:
                return action_result.set_status(phantom.APP_ERROR,
                        "Please provide valid comma-separated values in the action parameter. Max allowed length for each value is 1024.")
        return phantom.APP_SUCCESS

    def _handle_get_admin_users(self, param):
        """
        This action is used to fetch all admin users
        :param: No parameters
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, limit = self._validate_integer(action_result, param.get('limit', ZSCALER_MAX_PAGESIZE), ZSCALER_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        params = {}
        admin_users = []
        params['page'] = 1
        while True:
            if limit < ZSCALER_MAX_PAGESIZE:
                params['pageSize'] = limit
            else:
                params['pageSize'] = ZSCALER_MAX_PAGESIZE
            ret_val, get_admin_users = self._make_rest_call_helper('/api/v1/adminUsers', action_result, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            for admin_user in get_admin_users:
                admin_users.append(admin_user)
            limit = limit - params['pageSize']
            if limit <= 0 or len(get_admin_users) == 0:
                break
            params['page'] += 1

        for user in admin_users:
            action_result.add_data(user)
        summary = action_result.update_summary({})
        summary['total_admin_users'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_users(self, param):
        """
        This action is used to fetch all users
        :param name: User name
        :param dept: User department
        :param group: User group
        :param limit: Max number of users to retrieve
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not param:
            return action_result.set_status(phantom.APP_ERROR, "No filters provided")

        ret_val, limit = self._validate_integer(action_result, param.get('limit', ZSCALER_MAX_PAGESIZE), ZSCALER_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        params = {
            "name": param.get('name'),
            "dept": param.get('dept'),
            "group": param.get('group'),
            'page': 1
        }
        users = []
        while True:
            params['pageSize'] = min(limit, ZSCALER_MAX_PAGESIZE)
            ret_val, get_users = self._make_rest_call_helper('/api/v1/users', action_result, params=params, timeout_flag=1)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            for user in get_users:
                users.append(user)
            limit = limit - params['pageSize']
            if limit <= 0 or len(get_users) == 0:
                break
            params['page'] += 1

        # Add the response into the data section
        for user in users:
            action_result.add_data(user)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_users'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_groups(self, param):
        """
        This action is used to fetch groups based on search parameter
        :param search: Search string to match
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, limit = self._validate_integer(action_result, param.get('limit', ZSCALER_MAX_PAGESIZE), ZSCALER_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        params = {"search": param.get('search')}
        groups = []
        params['page'] = 1
        while True:
            params['pageSize'] = min(limit, ZSCALER_MAX_PAGESIZE)
            ret_val, get_groups = self._make_rest_call_helper('/api/v1/groups', action_result, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            for group in get_groups:
                groups.append(group)
            limit = limit - params['pageSize']
            if limit <= 0 or len(get_groups) == 0:
                break
            params['page'] += 1

        for group in groups:
            action_result.add_data(group)

        summary = action_result.update_summary({})
        summary['total_groups'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_group_user(self, param):
        """
        This action is used to add users to a group based on user id and group id
        :param user_id: User ID to add
        :param group_id: Group to add user tio
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']
        group_id = param['group_id']
        ret_val, user_response = self._make_rest_call_helper(f'/api/v1/users/{user_id}', action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        ret_val, group_response = self._make_rest_call_helper(f'/api/v1/groups/{group_id}', action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        summary = action_result.update_summary({})
        if group_response in user_response['groups']:
            summary['message'] = "User already in group"
            action_result.add_data(group_response)
            return action_result.set_status(phantom.APP_SUCCESS, "User already in group")
        user_response['groups'].append(group_response)
        data = user_response
        ret_val, response = self._make_rest_call_helper(f'/api/v1/users/{user_id}', action_result, data=data, method='put')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary['message'] = "User successfully added to group"
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_group_user(self, param):
        """
        This action is used to remove users from a group based on user id and group id
        :param user_id: User ID to remove
        :param group_id: Group to remove user from
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']
        group_id = param['group_id']
        ret_val, user_response = self._make_rest_call_helper(f'/api/v1/users/{user_id}', action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        if group_id not in [item['id'] for item in user_response['groups']]:
            summary['message'] = "User already removed from group"
            action_result.add_data(user_response)
            return action_result.set_status(phantom.APP_SUCCESS, "User already removed from group")

        for index, group in enumerate(user_response['groups']):
            if group_id == group['id']:
                user_response['groups'].pop(index)

        data = user_response
        ret_val, response = self._make_rest_call_helper(f'/api/v1/users/{user_id}', action_result, data=data, method='put')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary['message'] = "User removed from group"

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_url_categories':
            ret_val = self._handle_list_url_categories(param)

        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        elif action_id == 'block_ip':
            ret_val = self._handle_block_ip(param)

        elif action_id == 'block_url':
            ret_val = self._handle_block_url(param)

        elif action_id == 'unblock_ip':
            ret_val = self._handle_unblock_ip(param)

        elif action_id == 'unblock_url':
            ret_val = self._handle_unblock_url(param)

        elif action_id == 'allow_ip':
            ret_val = self._handle_allow_ip(param)

        elif action_id == 'allow_url':
            ret_val = self._handle_allow_url(param)

        elif action_id == 'unallow_ip':
            ret_val = self._handle_unallow_ip(param)

        elif action_id == 'unallow_url':
            ret_val = self._handle_unallow_url(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'lookup_url':
            ret_val = self._handle_lookup_url(param)

        elif action_id == 'submit_file':
            ret_val = self._handle_submit_file(param)

        elif action_id == 'get_admin_users':
            ret_val = self._handle_get_admin_users(param)

        elif action_id == 'get_users':
            ret_val = self._handle_get_users(param)

        elif action_id == 'get_groups':
            ret_val = self._handle_get_groups(param)

        elif action_id == 'add_group_user':
            ret_val = self._handle_add_group_user(param)

        elif action_id == 'remove_group_user':
            ret_val = self._handle_remove_group_user(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        config = self.get_config()
        self._base_url = config['base_url'].rstrip('/')
        self._username = config['username']
        self._password = config['password']
        self._api_key = config['api_key']
        self._sandbox_base_url = config.get('sandbox_base_url', None)
        if self._sandbox_base_url:
            self._sandbox_base_url = self._sandbox_base_url.rstrip('/')
        self._sandbox_api_token = config.get('sandbox_api_token', None)
        self._headers = {}
        self._retry_rest_call = True
        self.set_validator('ipv6', self._is_ip)

        return self._init_session()

    def finalize(self):

        self.save_state(self._state)
        return self._deinit_session()


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    verify = args.verify
    session_id = None

    if (args.username and args.password):
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(
                login_url, verify=verify, timeout=ZSCALER_DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']
            data = {'username': args.username, 'password': args.password, 'csrfmiddlewaretoken': csrftoken}
            headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url, verify=verify, data=data, headers=headers, timeout=ZSCALER_DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']

        except Exception as e:
            print(("Unable to get session id from the platform. Error: {0}".format(str(e))))
            sys.exit(1)

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        sys.exit(0)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ZscalerConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
