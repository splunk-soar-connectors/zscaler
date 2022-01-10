# File: zscaler_consts.py
#
# Copyright (c) 2017-2022 Splunk Inc.
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
ZSCALER_SANDBOX_FORCE_SUBMIT_FILE_MSG = "Please check if a verdict already exists for this file, "\
                "you can use the 'force' parameter to make the sandbox to reanalyze it."
ZSCALER_ERROR_CODE_MESSAGE = "Error code unavailable"
ZSCALER_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters"
TYPE_ERROR_MSG = "Error occurred while connecting to the Zscaler server. "\
    "Please check the asset configuration and|or the action parameters"
PARSE_ERROR_MSG = "Unable to parse the error message. "\
    "Please check the asset configuration and|or action parameters"
