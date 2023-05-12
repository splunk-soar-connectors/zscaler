# File: zscaler_consts.py
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
ZSCALER_JSON_FULL_DETAILS = 'Full Details'
ZSCLAER_ERR_MD5_UNKNOWN_MSG = 'md5 is unknown or analysis has yet not been completed'
ZSCALER_SANDBOX_GET_REPORT_MSG = 'Sandbox report successfully fetched for the provided md5 hash'
ZSCALER_SANDBOX_SUBMIT_FILE_MSG = "Successfully submitted the file to Sandbox"
ZSCALER_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
ZSCALER_STATE_FILE_CORRUPT_ERR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again."
)
ZSCALER_MAX_PAGESIZE = 1000
ZSCALER_DEFAULT_TIMEOUT = 30

# Constants relating to '_validate_integer'
ZSCALER_VALID_INTEGER_MSG = "Please provide a valid integer value in the {param}"
ZSCALER_NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {param}"
ZSCALER_POSITIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {param}"
ZSCALER_LIMIT_KEY = "'limit' action parameter"
