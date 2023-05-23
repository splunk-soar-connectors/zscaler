[comment]: # "Auto-generated SOAR connector documentation"
# Zscaler

Publisher: Splunk  
Connector Version: 2.4.0  
Product Vendor: Zscaler  
Product Name: Zscaler  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.0.0  

This app implements containment and investigative actions on Zscaler

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Below points are considered for providing the **URL Category** parameter value.

-   Entire URL category string has to be mentioned in block letters

-   The most child category on UI has to be passed as the URL category parameter value to the action

-   From the URL category value on UI, every space has to be replaced by an underscore '\_' before
    passing it in the action's parameter value

      

    -   For example, **Alternate Lifestyle** on UI becomes **ALTERNATE_LIFESTYLE**

-   When you specify a **url_category** , you can give it either the name you created or the ID
    which is assigned to it from Zscaler. The search will first search for the name, as opposed to
    the ID. So if you create a category **phantom-block** , you could use either **phantom-block**
    or **CUSTOM\_\*\*** . The name for these is case sensitive.

The following are considered for providing the **URL** parameter value.

-   The comma-separated values of **URL** should correctly be given e.g. test.com,test1.com else the
    Phantom framework's parameter validator will return the error mentioning **Exception occurred:
    string index out of range** .

Configure and set up permissions for the **lookup_url** action

-   Login to Zscaler UI using the Administrator credentials.
-   Once logged in, go to **Administration -> Role Management** section.
-   Click on the **Edit** icon beside the role that your account uses to configure the test
    connectivity.
-   Go to the **Functional Scope** section, enable **Security** if disabled, and save it.

The above steps would help run the Lookup URL action as expected.

The Sandbox Submission API requires a separate API key and uses a different host
(csbapi.\[zscaler-cloud-name\]). For the **submit_file** action, the **sandbox_base_url** and
**sandbox_api_token** asset configuration parameters should be configured. These two asset
parameters won't affect test_connectivity. Follow the below steps to fetch these credentials for the
**submit_file** action

-   Log in to the ZIA Admin Portal using your **admin** credentials.
-   Once logged in, go to **Administration -> Cloud Service API Key Management** section. In order
    to view the Cloud Service API Key Management page, the admin must be assigned an admin role.
-   For the Cloud Sandbox Submission API used in this action, the base URL and token are displayed
    on the **Sandbox Submission API Token** tab.
-   The base URL and token displayed here can be configured in the asset parameters in
    **sandbox_base_url** and **sandbox_api_token** parameters respectively and will be used for the
    submit_file action.

The above steps would help run the Submit File action as expected.

**NOTE:** This action would work according to the API behavior

Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Zscaler server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Zscaler asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Base URL (e.g. https://admin.zscaler_instance.net)
**api_key** |  required  | password | API Key
**username** |  required  | string | Username
**password** |  required  | password | Password
**sandbox_base_url** |  optional  | string | Sandbox Base URL
**sandbox_api_token** |  optional  | password | Sandbox API Token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get report](#action-get-report) - Fetch sandbox report for provided md5 file hash  
[list url categories](#action-list-url-categories) - List all URL categories  
[block ip](#action-block-ip) - Block an IP  
[block url](#action-block-url) - Block a URL  
[unblock ip](#action-unblock-ip) - Unblock an IP  
[unblock url](#action-unblock-url) - Unblock a URL  
[allow ip](#action-allow-ip) - Add an IP address to the allowlist  
[allow url](#action-allow-url) - Add a URL to the allowed list  
[unallow ip](#action-unallow-ip) - Remove an IP address from the allowlist  
[unallow url](#action-unallow-url) - Remove a URL from the allowed list  
[lookup ip](#action-lookup-ip) - Lookup the categories related to an IP  
[lookup url](#action-lookup-url) - Lookup the categories related to a URL  
[submit file](#action-submit-file) - Submit a file to Zscaler Sandbox  
[get admin users](#action-get-admin-users) - Get a list of admin users  
[get users](#action-get-users) - Gets a list of all users and allows user filtering by name, department, or group  
[get groups](#action-get-groups) - Gets a list of groups  
[add group user](#action-add-group-user) - Add user to group  
[remove group user](#action-remove-group-user) - Remove user from group  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get report'
Fetch sandbox report for provided md5 file hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_hash** |  required  | The md5 file hash | string |  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.file_hash | string |  `md5`  |   1043ca3fc2e83f0c6f100e46d2ea16be 
action_result.data.\*.Full Details.Classification.Category | string |  |   BENIGN 
action_result.data.\*.Full Details.Classification.DetectedMalware | string |  |  
action_result.data.\*.Full Details.Classification.Score | numeric |  |   10 
action_result.data.\*.Full Details.Classification.Type | string |  |   BENIGN 
action_result.data.\*.Full Details.FileProperties.DigitalCerificate | string |  |  
action_result.data.\*.Full Details.FileProperties.FileSize | numeric |  |   350084 
action_result.data.\*.Full Details.FileProperties.FileType | string |  |   EXE 
action_result.data.\*.Full Details.FileProperties.Issuer | string |  |  
action_result.data.\*.Full Details.FileProperties.MD5 | string |  `md5`  |   1043ca3fc2e83f0c6f100e46d2ea16be 
action_result.data.\*.Full Details.FileProperties.RootCA | string |  |  
action_result.data.\*.Full Details.FileProperties.SHA1 | string |  `sha1`  |   efbd493b33543341d43df6db4c92de2473cf49f3 
action_result.data.\*.Full Details.FileProperties.SSDeep | string |  |   6144:IFkS+8dpN9EtEnROO4T0LbTbHiXuFW0XPBGunX9v62HCTAA1PSahJj3zDbSJ8:CkMy4TGWXuFR5JAxS6Lnbu8 
action_result.data.\*.Full Details.FileProperties.Sha256 | string |  `sha256`  |   0e7fd4dde827a7f0bda82bbfbce4b92a551d0cd296f72e936b8968310d2181cd 
action_result.data.\*.Full Details.Origin.Country | string |  |   United States 
action_result.data.\*.Full Details.Origin.Language | string |  |   English 
action_result.data.\*.Full Details.Origin.Risk | string |  |   LOW 
action_result.data.\*.Full Details.Summary.Category | string |  |   EXECS 
action_result.data.\*.Full Details.Summary.Duration | numeric |  |   524114 
action_result.data.\*.Full Details.Summary.FileType | string |  |   EXE 
action_result.data.\*.Full Details.Summary.StartTime | numeric |  |   1520334357 
action_result.data.\*.Full Details.Summary.Status | string |  |   COMPLETED 
action_result.data.\*.Full Details.SystemSummary.\*.Risk | string |  |   LOW 
action_result.data.\*.Full Details.SystemSummary.\*.Signature | string |  |   Binary contains paths to development resources 
action_result.data.\*.Full Details.SystemSummary.\*.SignatureSources | string |  |   no activity detected 
action_result.summary | string |  |  
action_result.message | string |  |   Sandbox report successfully fetched for the provided md5 hash 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list url categories'
List all URL categories

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data.\*.configuredName | string |  |   Test-Caution 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customIpRangesCount | numeric |  |   0 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |   6.5.3.2.4 
action_result.data.\*.description | string |  |   OTHER_RESTRICTED_WEBSITE_DESC 
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  `zscaler url category`  |   OTHER_RESTRICTED_WEBSITE 
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric |  |   0 
action_result.data.\*.scopes.\*.Type | string |  |   ORGANIZATION 
action_result.data.\*.type | string |  |   URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   0 
action_result.data.\*.val | numeric |  |   1 
action_result.summary.total_url_categories | numeric |  |   97 
action_result.message | string |  |   Total url categories: 97 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'block ip'
Block an IP

Type: **contain**  
Read only: **False**

If a <b>url_category</b> is specified, it will add the IP(s) as a rule to that category. If it is left blank, it will instead add the IP(s) to the global blocklist.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   8.8.8.8, 208.67.222.222  aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   8.8.8.8 
action_result.summary.updated | string |  |   208.67.222.222 
action_result.message | string |  |   Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'block url'
Block a URL

Type: **contain**  
Read only: **False**

If a <b>url_category</b> is specified, it will add the URL(s) as a rule to that category. If it is left blank, it will instead add the URL(s) to the global blocklist.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `url list`  `domain` 
**url_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `url list`  `domain`  |   www.test.com  www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.type | string |  |   URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   3 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   www.test.com 
action_result.summary.updated | string |  |   www.test123.com 
action_result.message | string |  |   Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'unblock ip'
Unblock an IP

Type: **correct**  
Read only: **False**

If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global blocklist.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   8.8.8.8  8.8.8.8, 208.67.222.222  aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   8.8.8.8 
action_result.summary.updated | string |  |   208.67.222.222 
action_result.message | string |  |   Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'unblock url'
Unblock a URL

Type: **correct**  
Read only: **False**

If a <b>url_category</b> is specified, it will remove the URL(s) from that category. If it is left blank, it will instead remove the URL(s) from the global blocklist.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `url list`  `domain` 
**url_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `url list`  `domain`  |   www.test.com  www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.type | string |  |   URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   1 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   www.test.com 
action_result.summary.updated | string |  |   www.test123.com 
action_result.message | string |  |   Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'allow ip'
Add an IP address to the allowlist

Type: **contain**  
Read only: **False**

If a <b>url_category</b> is specified, it will add the IP(s) as a rule to that category. If it is left blank, it will instead add this IP(s) to the global allowlist.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   8.8.8.8  8.8.8.8, 208.67.222.222  aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   8.8.8.8 
action_result.summary.updated | string |  |   208.67.222.222 
action_result.message | string |  |   Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'allow url'
Add a URL to the allowed list

Type: **contain**  
Read only: **False**

If a <b>url_category</b> is specified, it will add the URL(s) as a rule to that category. If it is left blank, it will instead add the URL(s) to the global allowed list.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 
**url_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `domain`  `url list`  |   www.test.com  www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.type | string |  |   URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   3 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   www.test.com 
action_result.summary.updated | string |  |   www.test123.com 
action_result.message | string |  |   Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'unallow ip'
Remove an IP address from the allowlist

Type: **correct**  
Read only: **False**

If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global allowlist.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   8.8.8.8  8.8.8.8, 208.67.222.222  aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   8.8.8.8 
action_result.summary.updated | string |  |   208.67.222.222 
action_result.message | string |  |   Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'unallow url'
Remove a URL from the allowed list

Type: **correct**  
Read only: **False**

If a <b>url_category</b> is specified, it will remove the URL(s) from that category. If it is left blank, it will instead remove the URL(s) from the global allowed list.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 
**url_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `domain`  `url list`  |   www.test.com  www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   CUSTOM_01 
action_result.data.\*.configuredName | string |  |   Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   www.test.com 
action_result.summary.updated | string |  |   www.test123.com 
action_result.message | string |  |   Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'lookup ip'
Lookup the categories related to an IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   8.8.8.8  208.67.222.222, 8.8.8.8  aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.data.\*.blocklisted | boolean |  |   True  False 
action_result.data.\*.url | string |  `ip`  `ipv6`  |   208.67.222.222  8.8.8.8 
action_result.data.\*.urlClassifications | string |  |   WEB_SEARCH 
action_result.data.\*.urlClassificationsWithSecurityAlert | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully completed lookup 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'lookup url'
Lookup the categories related to a URL

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `domain`  `url list`  |   www.test.com, www.test3.com, test2.tv 
action_result.data.\*.blocklisted | boolean |  |   True  False 
action_result.data.\*.url | string |  `url`  `domain`  `url list`  |   www.test.com 
action_result.data.\*.urlClassifications | string |  |   MISCELLANEOUS_OR_UNKNOWN 
action_result.data.\*.urlClassificationsWithSecurityAlert | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully completed lookup 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'submit file'
Submit a file to Zscaler Sandbox

Type: **generic**  
Read only: **False**

This action requires a Sandbox Submission API token. By default, files are scanned by Zscaler antivirus (AV) and submitted directly to the sandbox in order to obtain a verdict. However, if a verdict already exists for the file, you can use the 'force' parameter to make the sandbox to reanalyze it. You can submit up to 100 files per day.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** |  required  | Vault ID of file to submit | string |  `vault id`  `sha1` 
**force** |  optional  | Submit file to sandbox even if found malicious during AV scan and a verdict already exists | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.force | boolean |  |   True  False 
action_result.parameter.vault_id | string |  `vault id`  `sha1`  |   30c5e524e975816fbce1d958150e394efc219772 
action_result.data.\*.code | numeric |  |   200 
action_result.data.\*.fileType | string |  |   zip 
action_result.data.\*.md5 | string |  `md5`  |   6CE6F415D8475545BE5BA114F208B0FF 
action_result.data.\*.message | string |  |   /submit response OK 
action_result.data.\*.sandboxSubmission | string |  |   Virus 
action_result.data.\*.virusName | string |  |   EICAR_Test_File 
action_result.data.\*.virusType | string |  |   Virus 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully submitted the file to Sandbox 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get admin users'
Get a list of admin users

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum number of records to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   1000 
action_result.data.\*.adminScopeScopeEntities.\*.id | numeric |  |   4460340 
action_result.data.\*.adminScopeScopeEntities.\*.name | string |  |   Example App 
action_result.data.\*.adminScopeType | string |  |  
action_result.data.\*.adminScopescopeGroupMemberEntities.\*.id | numeric |  |   8035054 
action_result.data.\*.comments | string |  |   This is test user 
action_result.data.\*.disabled | boolean |  |   True 
action_result.data.\*.email | string |  `email`  |   first.last@emaildomain.com 
action_result.data.\*.id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.isDefaultAdmin | boolean |  |   True 
action_result.data.\*.isDeprecatedDefaultAdmin | boolean |  |   True 
action_result.data.\*.isExecMobileAppEnabled | boolean |  |   True 
action_result.data.\*.isNonEditable | boolean |  |   True  False 
action_result.data.\*.isPasswordLoginAllowed | boolean |  |   True  False 
action_result.data.\*.isProductUpdateCommEnabled | boolean |  |   True 
action_result.data.\*.isSecurityReportCommEnabled | boolean |  |   True 
action_result.data.\*.isServiceUpdateCommEnabled | boolean |  |   True 
action_result.data.\*.loginName | string |  |   first.last@domain.com 
action_result.data.\*.name | string |  |   new_test_long_email_id_new_test_long_email_id_new_test_long_email_id_new_test_long_email 
action_result.data.\*.pwdLastModifiedTime | numeric |  |  
action_result.data.\*.role.extensions.adminRank | string |  |  
action_result.data.\*.role.extensions.roleType | string |  |  
action_result.data.\*.role.id | numeric |  |  
action_result.data.\*.role.isNameL10nTag | boolean |  |   True 
action_result.data.\*.role.name | string |  |   Super Admin 
action_result.data.\*.userName | string |  |   Last, First 
action_result.summary.total_admin_users | numeric |  |   10 
action_result.message | string |  |   Total admin users: 100 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get users'
Gets a list of all users and allows user filtering by name, department, or group

Type: **investigate**  
Read only: **True**

Gets a list of all users and allows user filtering by name, department, or group. The name search parameter performs a partial match. The dept and group parameters perform a 'starts with' match.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  optional  | User Name/ID | string | 
**dept** |  optional  | User department | string | 
**group** |  optional  | User group | string | 
**limit** |  optional  | Maximum number of records to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.dept | string |  |   Service Admin 
action_result.parameter.group | string |  |   Service Admin 
action_result.parameter.limit | numeric |  |   1000 
action_result.parameter.name | string |  |   Example test 
action_result.data.\*.adminUser | boolean |  |   True  False 
action_result.data.\*.comments | string |  |   This is test user 
action_result.data.\*.deleted | boolean |  |   True  False 
action_result.data.\*.department.id | numeric |  |   81896690 
action_result.data.\*.department.name | string |  |   IT 
action_result.data.\*.disabled | boolean |  |   True 
action_result.data.\*.email | string |  `email`  |   first.last@domain.com 
action_result.data.\*.groups.\*.id | numeric |  `zscaler group id`  |   8894813 
action_result.data.\*.groups.\*.name | string |  |   Super Admin 
action_result.data.\*.id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.isNonEditable | boolean |  |   True  False 
action_result.data.\*.name | string |  |   First Last 
action_result.summary.total_users | numeric |  |   10 
action_result.message | string |  |   Total users: 0 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get groups'
Gets a list of groups

Type: **investigate**  
Read only: **True**

Gets a list of groups. The search parameters find matching values in the name or comments attributes.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search** |  optional  | The search string used to match against a group's name or comments attributes | string | 
**limit** |  optional  | Maximum number of records to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   100 
action_result.parameter.search | string |  |   Example_test 
action_result.data.\*.comments | string |  |   This is for testing 
action_result.data.\*.id | numeric |  `zscaler group id`  |   8894813 
action_result.data.\*.isNonEditable | boolean |  |   True 
action_result.data.\*.name | string |  |   Frothly Internet Access 
action_result.summary.total_groups | numeric |  |   4 
action_result.message | string |  |   Total groups: 4 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'add group user'
Add user to group

Type: **generic**  
Read only: **False**

Add a group to the user's profile.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | ZScaler User ID | numeric |  `zscaler user id` 
**group_id** |  required  | ZScaler Group ID | numeric |  `zscaler group id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_id | numeric |  `zscaler group id`  |   8894813 
action_result.parameter.user_id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.adminUser | boolean |  |   True 
action_result.data.\*.deleted | boolean |  |   False 
action_result.data.\*.department.id | numeric |  |   4459551 
action_result.data.\*.department.name | string |  |   Service Admin 
action_result.data.\*.email | string |  |   134@example.us 
action_result.data.\*.groups.\*.id | numeric |  |   4460341 
action_result.data.\*.groups.\*.name | string |  |   Example App 
action_result.data.\*.id | numeric |  |   9840695 
action_result.data.\*.name | string |  |   Test user 
action_result.summary | string |  |  
action_result.summary.message | string |  |   User successfully added to group 
action_result.message | string |  |   User successfully added to group 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'remove group user'
Remove user from group

Type: **correct**  
Read only: **False**

Remove a group from the user's profile.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | ZScaler User Id | numeric |  `zscaler user id` 
**group_id** |  required  | ZScaler Group Id | numeric |  `zscaler group id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_id | numeric |  `zscaler group id`  |   8894813 
action_result.parameter.user_id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.adminUser | boolean |  |   True 
action_result.data.\*.deleted | boolean |  |   False 
action_result.data.\*.department.id | numeric |  |   4459551 
action_result.data.\*.department.name | string |  |   Service Admin 
action_result.data.\*.email | string |  |   134@example.us 
action_result.data.\*.groups.\*.id | numeric |  |   4459550 
action_result.data.\*.groups.\*.name | string |  |   Service Admin 
action_result.data.\*.id | numeric |  |   9840695 
action_result.data.\*.name | string |  |   Elsie 
action_result.summary | string |  |  
action_result.summary.message | string |  |   User removed from group 
action_result.message | string |  |   User removed from group 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 