# --
# File: zscaler_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup

import time


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

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        try:
            message = resp_json['message']
        except:
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}')
            )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

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

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        resp_json = None

        if headers is None:
            headers = {}

        headers.update(self._headers)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                json=data,
                headers=headers,
                params=params
            )
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

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
        #  1. There is a maximum limt of requests per second, depending on if its a GET / POST / PUT / DETE
        #  2. There is a maximum number of requests per hour
        # Regardless, the response will include a try-after value, which we can use to sleep
        ret_val, response = self._make_rest_call(*args, **kwargs)
        if phantom.is_fail(ret_val):
            if self._response is None:
                return ret_val, response
            if self._response.status_code == 409:  # Lock not available
                # This basically just means we need to try again
                self.debug_print("Error 409: Lock not available")
                self.send_progress("Error 409: Lock not available: Retrying in 1 second")
                time.sleep(1)
                return self._make_rest_call_helper(*args, **kwargs)
            if self._response.status_code == 429:  # Rate limit exceeded
                try:
                    retry_time = self._response.json()['Retry-After']
                except KeyError:
                    self.debug_print("KeyError")
                    return ret_val, response
                self.debug_print("Retry Time: {}".format(retry_time))
                seconds_to_wait = self._parse_retry_time(retry_time)
                if seconds_to_wait is None:
                    return retry_time, response
                self.send_progress("Exceeded rate limit: Retrying after {}".format(retry_time))
                time.sleep(seconds_to_wait)
                return self._make_rest_call_helper(*args, **kwargs)

        return ret_val, response

    def _obfuscate_api_key(self, api_key):
        now = str(long(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(n), 1):
            key += api_key[int(n[i])]
        for j in range(0, len(r), 1):
            key += api_key[int(r[j]) + 2]

        return now, key

    def _init_session(self):
        config = self.get_config()
        username = config['username']
        password = config['password']
        api_key = config['api_key']
        try:
            timestamp, obf_api_key = self._obfuscate_api_key(api_key)
        except:
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
            self.save_progress('Error starting Zscaler session: {}'.format(action_result.get_message()))
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
        ret_val, response = self._make_rest_call_helper('/api/v1/authenticatedSession', action_result, method='delete')  # noqa
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        # If we are here we have successfully initialized a session
        self.save_progress("Connectivity test passed")
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

    def _get_blacklist(self, action_result):
        return self._make_rest_call_helper('/api/v1/security/advanced', action_result)

    def _check_blacklist(self, action_result, endpoints, action):
        ret_val, response = self._get_blacklist(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(ret_val, None)

        blacklist = response.get('blacklistUrls', [])

        return self._filter_endpoints(action_result, endpoints, blacklist, action, 'Blacklist')

    def _amend_blacklist(self, action_result, endpoints, action):
        ret_val, filtered_endpoints = self._check_blacklist(action_result, endpoints, action)
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
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_whitelist(self, action_result):
        return self._make_rest_call_helper('/api/v1/security', action_result)

    def _check_whitelist(self, action_result, endpoints, action):
        ret_val, response = self._get_whitelist(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(ret_val, None)

        whitelist = response.get('whitelistUrls', [])
        self._whitelist = whitelist

        return self._filter_endpoints(action_result, endpoints, whitelist, action, 'Whitelist')

    def _amend_whitelist(self, action_result, endpoints, action):
        ret_val, filtered_endpoints = self._check_whitelist(action_result, endpoints, action)
        if phantom.is_fail(ret_val) or filtered_endpoints is None:
            return ret_val

        if action == "ADD_TO_LIST":
            to_add_endpoints = list(set(self._whitelist + filtered_endpoints))
        else:
            to_add_endpoints = list(set(self._whitelist) - set(filtered_endpoints))

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

        data = self._category

        if action == "ADD_TO_LIST":
            to_add_endpoints = list(set(data.get('dbCategorizedUrls', []) + filtered_endpoints))
        else:
            to_add_endpoints = list(set(data.get('dbCategorizedUrls', [])) - set(filtered_endpoints))

        data['dbCategorizedUrls'] = to_add_endpoints
        ret_val, response = self._make_rest_call_helper(
            '/api/v1/urlCategories/{}'.format(self._category['id']),
            action_result, data=data, method='put'
        )
        if phantom.is_fail(ret_val):
            return ret_val
        action_result.add_data(response)
        summary = action_result.set_summary({})
        summary['updated'] = filtered_endpoints
        summary['ignored'] = list(set(endpoints) - set(filtered_endpoints))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _block_endpoint(self, action_result, endpoints, category):
        endpoints = [x.strip() for x in endpoints.split(',')]
        if category is None:
            return self._amend_blacklist(action_result, endpoints, 'ADD_TO_LIST')
        else:
            return self._amend_category(action_result, endpoints, category, 'ADD_TO_LIST')

    def _unblock_endpoint(self, action_result, endpoints, category):
        endpoints = [x.strip() for x in endpoints.split(',')]
        if category is None:
            return self._amend_blacklist(action_result, endpoints, 'REMOVE_FROM_LIST')
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

    def _whitelist_endpoint(self, action_result, endpoints, category):
        endpoints = [x.strip() for x in endpoints.split(',')]
        if category is None:
            return self._amend_whitelist(action_result, endpoints, 'ADD_TO_LIST')
        else:
            return self._amend_category(action_result, endpoints, category, 'ADD_TO_LIST')

    def _unwhitelist_endpoint(self, action_result, endpoints, category):
        endpoints = [x.strip() for x in endpoints.split(',')]
        if category is None:
            return self._amend_whitelist(action_result, endpoints, 'REMOVE_FROM_LIST')
        else:
            return self._amend_category(action_result, endpoints, category, 'REMOVE_FROM_LIST')

    def _handle_whitelist_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._whitelist_endpoint(action_result, param['ip'], param.get('url_category'))

    def _handle_whitelist_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._whitelist_endpoint(action_result, param['url'], param.get('url_category'))

    def _handle_unwhitelist_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._unwhitelist_endpoint(action_result, param['ip'], param.get('url_category'))

    def _handle_unwhitelist_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._unwhitelist_endpoint(action_result, param['url'], param.get('url_category'))

    def _lookup_endpoint(self, action_result, endpoints):
        endpoints = [x.strip() for x in endpoints.split(',')]
        ret_val, response = self._make_rest_call_helper(
            '/api/v1/urlLookup', action_result,
            data=endpoints, method='post'
        )
        if phantom.is_fail(ret_val):
            return ret_val

        action_result.update_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully completed lookup")

    def _handle_lookup_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._lookup_endpoint(action_result, param['ip'])

    def _handle_lookup_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        return self._lookup_endpoint(action_result, param['url'])

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'block_ip':
            ret_val = self._handle_block_ip(param)

        elif action_id == 'block_url':
            ret_val = self._handle_block_url(param)

        elif action_id == 'unblock_ip':
            ret_val = self._handle_unblock_ip(param)

        elif action_id == 'unblock_url':
            ret_val = self._handle_unblock_url(param)

        elif action_id == 'block_ip2':
            ret_val = self._handle_block_ip(param)

        elif action_id == 'block_url2':
            ret_val = self._handle_block_url(param)

        elif action_id == 'unblock_ip2':
            ret_val = self._handle_unblock_ip(param)

        elif action_id == 'unblock_url2':
            ret_val = self._handle_unblock_url(param)

        elif action_id == 'whitelist_ip':
            ret_val = self._handle_whitelist_ip(param)

        elif action_id == 'whitelist_url':
            ret_val = self._handle_whitelist_url(param)

        elif action_id == 'unwhitelist_ip':
            ret_val = self._handle_unwhitelist_ip(param)

        elif action_id == 'unwhitelist_url':
            ret_val = self._handle_unwhitelist_url(param)

        elif action_id == "lookup_ip":
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'lookup_url':
            ret_val = self._handle_lookup_url(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config['base_url'].rstrip('/')
        self._username = config['username']
        self._password = config['password']
        self._headers = {}
        return self._init_session()

    def finalize(self):

        self.save_state(self._state)
        return self._deinit_session()


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ZscalerConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
