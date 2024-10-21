[comment]: # "Auto-generated SOAR connector documentation"
# Zscaler

Publisher: Splunk  
Connector Version: 3.0.0  
Product Vendor: Zscaler  
Product Name: Zscaler  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.2  

This app implements containment and investigative actions on Zscaler

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2024 Splunk Inc."
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
[get allowlist](#action-get-allowlist) - Get urls on the allow list  
[get denylist](#action-get-denylist) - Get urls on the deny list  
[update user](#action-update-user) - Update user with given id  
[add category url](#action-add-category-url) - Add urls to a cetgory  
[add category ip](#action-add-category-ip) - Add IPs to a cetgory  
[remove category url](#action-remove-category-url) - Add urls to a cetgory  
[remove category ip](#action-remove-category-ip) - Remove IPs to a cetgory  
[create destination group](#action-create-destination-group) - Create destination group  
[list destination group](#action-list-destination-group) - List destination group  
[edit destination group](#action-edit-destination-group) - Edit destination group  
[delete destination group](#action-delete-destination-group) - Delete destination group  
[get departments](#action-get-departments) - Get a list of departments  
[get category details](#action-get-category-details) - Get the urls and keywords of a category  

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
action_result.status | string |  |   test success  test failed 
action_result.parameter.file_hash | string |  `md5`  |   test 1043ca3fc2e83f0c6f100e46d2ea16be 
action_result.data.\*.Full Details.Classification.Category | string |  |   test BENIGN 
action_result.data.\*.Full Details.Classification.DetectedMalware | string |  |  
action_result.data.\*.Full Details.Classification.Score | numeric |  |   10 
action_result.data.\*.Full Details.Classification.Type | string |  |   test BENIGN 
action_result.data.\*.Full Details.FileProperties.DigitalCerificate | string |  |  
action_result.data.\*.Full Details.FileProperties.FileSize | numeric |  |   350084 
action_result.data.\*.Full Details.FileProperties.FileType | string |  |   test EXE 
action_result.data.\*.Full Details.FileProperties.Issuer | string |  |  
action_result.data.\*.Full Details.FileProperties.MD5 | string |  `md5`  |   test 1043ca3fc2e83f0c6f100e46d2ea16be 
action_result.data.\*.Full Details.FileProperties.RootCA | string |  |  
action_result.data.\*.Full Details.FileProperties.SHA1 | string |  `sha1`  |   test efbd493b33543341d43df6db4c92de2473cf49f3 
action_result.data.\*.Full Details.FileProperties.SSDeep | string |  |   test 6144:IFkS+8dpN9EtEnROO4T0LbTbHiXuFW0XPBGunX9v62HCTAA1PSahJj3zDbSJ8:CkMy4TGWXuFR5JAxS6Lnbu8 
action_result.data.\*.Full Details.FileProperties.Sha256 | string |  `sha256`  |   test 0e7fd4dde827a7f0bda82bbfbce4b92a551d0cd296f72e936b8968310d2181cd 
action_result.data.\*.Full Details.Origin.Country | string |  |   test United States 
action_result.data.\*.Full Details.Origin.Language | string |  |   test English 
action_result.data.\*.Full Details.Origin.Risk | string |  |   test LOW 
action_result.data.\*.Full Details.Summary.Category | string |  |   test EXECS 
action_result.data.\*.Full Details.Summary.Duration | numeric |  |   524114 
action_result.data.\*.Full Details.Summary.FileType | string |  |   test EXE 
action_result.data.\*.Full Details.Summary.StartTime | numeric |  |   1520334357 
action_result.data.\*.Full Details.Summary.Status | string |  |   test COMPLETED 
action_result.data.\*.Full Details.SystemSummary.\*.Risk | string |  |   test LOW 
action_result.data.\*.Full Details.SystemSummary.\*.Signature | string |  |   test Binary contains paths to development resources 
action_result.data.\*.Full Details.SystemSummary.\*.SignatureSources | string |  |   test no activity detected 
action_result.summary | string |  |  
action_result.message | string |  |   test Sandbox report successfully fetched for the provided md5 hash 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list url categories'
List all URL categories

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**get_ids_and_names_only** |  optional  | Whether to retrieve only a list containing URL category IDs and names. Even if displayURL is set to true, URLs will not be returned | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.get_ids_and_names_only | string |  |   RADIO_STATIONS 
action_result.data.\*.configuredName | string |  |   test Test-Caution 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customIpRangesCount | numeric |  |   0 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |   test 6.5.3.2.4 
action_result.data.\*.description | string |  |   test OTHER_RESTRICTED_WEBSITE_DESC 
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  `zscaler url category`  |   test OTHER_RESTRICTED_WEBSITE 
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric |  |   0 
action_result.data.\*.scopes.\*.Type | string |  |   test ORGANIZATION 
action_result.data.\*.type | string |  |   test URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   0 
action_result.data.\*.val | numeric |  |   1 
action_result.summary.total_url_categories | numeric |  |   97 
action_result.message | string |  |   test Total url categories: 97 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   test 8.8.8.8, 208.67.222.222  test aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test 8.8.8.8 
action_result.summary.updated | string |  |   test 208.67.222.222 
action_result.message | string |  |   test Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.url | string |  `url`  `url list`  `domain`  |   test www.test.com  www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.type | string |  |   test URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   3 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test www.test.com 
action_result.summary.updated | string |  |   test www.test123.com 
action_result.message | string |  |   test Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   test 8.8.8.8  test 8.8.8.8, 208.67.222.222  test aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test 8.8.8.8 
action_result.summary.updated | string |  |   test 208.67.222.222 
action_result.message | string |  |   test Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.url | string |  `url`  `url list`  `domain`  |   test www.test.com  www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Block 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.type | string |  |   test URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   1 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test www.test.com 
action_result.summary.updated | string |  |   test www.test123.com 
action_result.message | string |  |   test Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   test 8.8.8.8  test 8.8.8.8, 208.67.222.222  test aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test 8.8.8.8 
action_result.summary.updated | string |  |   test 208.67.222.222 
action_result.message | string |  |   test Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.url | string |  `url`  `domain`  `url list`  |   test www.test.com  test www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.type | string |  |   test URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   3 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test www.test.com 
action_result.summary.updated | string |  |   test www.test123.com 
action_result.message | string |  |   test Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   test 8.8.8.8  test 8.8.8.8, 208.67.222.222  test aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test 8.8.8.8 
action_result.summary.updated | string |  |   test 208.67.222.222 
action_result.message | string |  |   test Ignored: ['8.8.8.8'], Updated: ['208.67.222.222'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.url | string |  `url`  `domain`  `url list`  |   test www.test.com  test www.test.com, www.test123.com 
action_result.parameter.url_category | string |  `zscaler url category`  |   test CUSTOM_01 
action_result.data.\*.configuredName | string |  |   test Test-Allowlist 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.id | string |  |   test CUSTOM_01 
action_result.data.\*.val | numeric |  |   128 
action_result.summary.ignored | string |  |   test www.test.com 
action_result.summary.updated | string |  |   test www.test123.com 
action_result.message | string |  |   test Ignored: ['www.test.com'], Updated: ['www.test123.com'] 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   test 8.8.8.8  test 208.67.222.222, 8.8.8.8  test aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa 
action_result.data.\*.blocklisted | boolean |  |   True  False 
action_result.data.\*.url | string |  `ip`  `ipv6`  |   test 208.67.222.222  test 8.8.8.8 
action_result.data.\*.urlClassifications | string |  |   test WEB_SEARCH 
action_result.data.\*.urlClassificationsWithSecurityAlert | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   test Successfully completed lookup 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.url | string |  `url`  `domain`  `url list`  |   test www.test.com, www.test3.com, test2.tv 
action_result.data.\*.blocklisted | boolean |  |   True  False 
action_result.data.\*.url | string |  `url`  `domain`  `url list`  |   test www.test.com 
action_result.data.\*.urlClassifications | string |  |   test MISCELLANEOUS_OR_UNKNOWN 
action_result.data.\*.urlClassificationsWithSecurityAlert | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   test Successfully completed lookup 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.force | boolean |  |   True  False 
action_result.parameter.vault_id | string |  `vault id`  `sha1`  |   test 30c5e524e975816fbce1d958150e394efc219772 
action_result.data.\*.code | numeric |  |   200 
action_result.data.\*.fileType | string |  |   test zip 
action_result.data.\*.md5 | string |  `md5`  |   test 6CE6F415D8475545BE5BA114F208B0FF 
action_result.data.\*.message | string |  |   test /submit response OK 
action_result.data.\*.sandboxSubmission | string |  |   test Virus 
action_result.data.\*.virusName | string |  |   test EICAR_Test_File 
action_result.data.\*.virusType | string |  |   test Virus 
action_result.summary | string |  |  
action_result.message | string |  |   test Successfully submitted the file to Sandbox 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.limit | numeric |  |   1000 
action_result.data.\*.adminScopeScopeEntities.\*.id | numeric |  |   4460340 
action_result.data.\*.adminScopeScopeEntities.\*.name | string |  |   test Example App 
action_result.data.\*.adminScopeType | string |  |  
action_result.data.\*.adminScopescopeGroupMemberEntities.\*.id | numeric |  |   8035054 
action_result.data.\*.comments | string |  |   test This is test user 
action_result.data.\*.disabled | boolean |  |   True 
action_result.data.\*.email | string |  `email`  |   test first.last@emaildomain.com 
action_result.data.\*.id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.isDefaultAdmin | boolean |  |   True 
action_result.data.\*.isDeprecatedDefaultAdmin | boolean |  |   True 
action_result.data.\*.isExecMobileAppEnabled | boolean |  |   True 
action_result.data.\*.isNonEditable | boolean |  |   True  False 
action_result.data.\*.isPasswordLoginAllowed | boolean |  |   True  False 
action_result.data.\*.isProductUpdateCommEnabled | boolean |  |   True 
action_result.data.\*.isSecurityReportCommEnabled | boolean |  |   True 
action_result.data.\*.isServiceUpdateCommEnabled | boolean |  |   True 
action_result.data.\*.loginName | string |  |   test first.last@domain.com 
action_result.data.\*.name | string |  |   test new_test_long_email_id_new_test_long_email_id_new_test_long_email_id_new_test_long_email 
action_result.data.\*.pwdLastModifiedTime | numeric |  |  
action_result.data.\*.role.extensions.adminRank | string |  |  
action_result.data.\*.role.extensions.roleType | string |  |  
action_result.data.\*.role.id | numeric |  |  
action_result.data.\*.role.isNameL10nTag | boolean |  |   True 
action_result.data.\*.role.name | string |  |   test Super Admin 
action_result.data.\*.userName | string |  |   test Last, First 
action_result.summary.total_admin_users | numeric |  |   10 
action_result.message | string |  |   test Total admin users: 100 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.dept | string |  |   test Service Admin 
action_result.parameter.group | string |  |   test Service Admin 
action_result.parameter.limit | numeric |  |   1000 
action_result.parameter.name | string |  |   test Example test 
action_result.data.\*.adminUser | boolean |  |   True  False 
action_result.data.\*.comments | string |  |   test This is test user 
action_result.data.\*.deleted | boolean |  |   True  False 
action_result.data.\*.department.id | numeric |  |   81896690 
action_result.data.\*.department.name | string |  |   test IT 
action_result.data.\*.disabled | boolean |  |   True 
action_result.data.\*.email | string |  `email`  |   test first.last@domain.com 
action_result.data.\*.groups.\*.id | numeric |  `zscaler group id`  |   8894813 
action_result.data.\*.groups.\*.name | string |  |   test Super Admin 
action_result.data.\*.id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.isNonEditable | boolean |  |   True  False 
action_result.data.\*.name | string |  |   test First Last 
action_result.summary.total_users | numeric |  |   10 
action_result.message | string |  |   test Total users: 0 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.limit | numeric |  |   100 
action_result.parameter.search | string |  |   test Example_test 
action_result.data.\*.comments | string |  |   test This is for testing 
action_result.data.\*.id | numeric |  `zscaler group id`  |   8894813 
action_result.data.\*.isNonEditable | boolean |  |   True 
action_result.data.\*.name | string |  |   test Frothly Internet Access 
action_result.summary.total_groups | numeric |  |   4 
action_result.message | string |  |   test Total groups: 4 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.group_id | numeric |  `zscaler group id`  |   8894813 
action_result.parameter.user_id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.adminUser | boolean |  |   True 
action_result.data.\*.deleted | boolean |  |   False 
action_result.data.\*.department.id | numeric |  |   4459551 
action_result.data.\*.department.name | string |  |   test Service Admin 
action_result.data.\*.email | string |  |   test 134@example.us 
action_result.data.\*.groups.\*.id | numeric |  |   4460341 
action_result.data.\*.groups.\*.name | string |  |   test Example App 
action_result.data.\*.id | numeric |  |   9840695 
action_result.data.\*.name | string |  |   test Test user 
action_result.summary | string |  |  
action_result.summary.message | string |  |   test User successfully added to group 
action_result.message | string |  |   test User successfully added to group 
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
action_result.status | string |  |   test success  test failed 
action_result.parameter.group_id | numeric |  `zscaler group id`  |   8894813 
action_result.parameter.user_id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.adminUser | boolean |  |   True 
action_result.data.\*.deleted | boolean |  |   False 
action_result.data.\*.department.id | numeric |  |   4459551 
action_result.data.\*.department.name | string |  |   test Service Admin 
action_result.data.\*.email | string |  |   test 134@example.us 
action_result.data.\*.groups.\*.id | numeric |  |   4459550 
action_result.data.\*.groups.\*.name | string |  |   test Service Admin 
action_result.data.\*.id | numeric |  |   9840695 
action_result.data.\*.name | string |  |   test Elsie 
action_result.summary | string |  |  
action_result.summary.message | string |  |   test User removed from group 
action_result.message | string |  |   test User removed from group 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get allowlist'
Get urls on the allow list

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.data.\*.url | string |  |  
action_result.summary.total_allowlist_items | numeric |  |   10 
action_result.summary.message | string |  |   Allowlist retrieved 
action_result.message | string |  |   Allowlist retrieved 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get denylist'
Get urls on the deny list

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | Filter results be url or ip | string | 
**query** |  optional  | Regular expression to match url or ip against | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.query | string |  |   8...8 
action_result.parameter.filter | string |  |  
action_result.data.\*.url | string |  |  
action_result.summary.message | string |  |   Blacklist retrieved 
action_result.message | string |  |   Denylist retrieved 
action_result.summary.total_denylist_items | numeric |  |   10 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update user'
Update user with given id

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | ZScaler User Id | numeric |  `zscaler user id` 
**user** |  optional  | JSON object containing the user details (see https://help.zscaler.com/zia/user-management#/users/{userId}-put) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.user | string |  |  
action_result.parameter.user_id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.adminUser | boolean |  |   True  False 
action_result.data.\*.comments | string |  |   test This is test user 
action_result.data.\*.deleted | boolean |  |   True  False 
action_result.data.\*.department.id | numeric |  |   81896690 
action_result.data.\*.department.name | string |  |   test IT 
action_result.data.\*.email | string |  `email`  |   test first.last@domain.com 
action_result.data.\*.groups.\*.id | numeric |  `zscaler group id`  |   8894813 
action_result.data.\*.groups.\*.name | string |  |   test Super Admin 
action_result.data.\*.id | numeric |  `zscaler user id`  |   889814 
action_result.data.\*.name | string |  |   test First Last 
action_result.summary | string |  |  
action_result.summary.message | string |  |   test User removed from group 
action_result.message | string |  |   test User removed from group 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'add category url'
Add urls to a cetgory

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** |  required  | The ID of the category to add the specified URLs to | string | 
**urls** |  optional  | A comma-separated list of URLs to add to the specified category | string | 
**retaining-parent-category-url** |  optional  | A comma-separated list of URLs to add to the retaining parent category section inside the specified category | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.category_id | string |  |   RADIO_STATIONS 
action_result.parameter.urls | string |  |  
action_result.parameter.retaining-parent-category-url | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.val | numeric |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.urls | string |  |  
action_result.data.\*.scopes.\*.Type | string |  |  
action_result.data.\*.editable | boolean |  |  
action_result.data.\*.keywords | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.configuredName | string |  |  
action_result.data.\*.customCategory | boolean |  |  
action_result.data.\*.customUrlsCount | numeric |  |  
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.customIpRangesCount | numeric |  |  
action_result.data.\*.keywordsRetainingParentCategory | string |  |  
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |  
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric |  |  
action_result.message | string |  |   Message: Category urs updated 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'add category ip'
Add IPs to a cetgory

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** |  required  | The ID of the category to add the specified URLs to | string | 
**ips** |  optional  | A comma-separated list of IP addresses to add to the specified category | string | 
**retaining-parent-category-ip** |  optional  | A comma-separated list of IPs to add to the retaining parent category section inside the specified category | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.category_id | string |  |   RADIO_STATIONS 
action_result.parameter.ips | string |  |  
action_result.parameter.retaining-parent-category-ip | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.val | numeric |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.urls | string |  |  
action_result.data.\*.scopes.\*.Type | string |  |  
action_result.data.\*.editable | boolean |  |  
action_result.data.\*.keywords | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.configuredName | string |  |  
action_result.data.\*.customCategory | boolean |  |  
action_result.data.\*.customUrlsCount | numeric |  |  
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.customIpRangesCount | numeric |  |  
action_result.data.\*.keywordsRetainingParentCategory | string |  |  
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |  
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric |  |  
action_result.message | string |  |   Message: Category ips updated 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'remove category url'
Add urls to a cetgory

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** |  required  | The ID of the category to add the specified URLs to | string | 
**urls** |  optional  | A comma-separated list of URLs to remove from the specified category | string | 
**retaining-parent-category-url** |  optional  | A comma-separated list of URLs to remove from the retaining parent category section inside the specified category | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.category_id | string |  |   RADIO_STATIONS 
action_result.parameter.urls | string |  |  
action_result.parameter.retaining-parent-category-url | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.val | numeric |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.urls | string |  |  
action_result.data.\*.scopes.\*.Type | string |  |  
action_result.data.\*.editable | boolean |  |  
action_result.data.\*.keywords | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.configuredName | string |  |  
action_result.data.\*.customCategory | boolean |  |  
action_result.data.\*.customUrlsCount | numeric |  |  
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.customIpRangesCount | numeric |  |  
action_result.data.\*.keywordsRetainingParentCategory | string |  |  
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |  
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric |  |  
action_result.message | string |  |   Message: Category urls removed 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'remove category ip'
Remove IPs to a cetgory

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_id** |  required  | The ID of the category to add the specified URLs to | string | 
**ips** |  optional  | A comma-separated list of IP addresses to add to the specified category | string | 
**retaining-parent-category-ip** |  optional  | A comma-separated list of IPs to add to the retaining parent category section inside the specified category | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.category_id | string |  |   RADIO_STATIONS 
action_result.parameter.ips | string |  |  
action_result.parameter.retaining-parent-category-ip | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.val | numeric |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.urls | string |  |  
action_result.data.\*.scopes.\*.Type | string |  |  
action_result.data.\*.editable | boolean |  |  
action_result.data.\*.keywords | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.configuredName | string |  |  
action_result.data.\*.customCategory | boolean |  |  
action_result.data.\*.customUrlsCount | numeric |  |  
action_result.data.\*.dbCategorizedUrls | string |  |  
action_result.data.\*.customIpRangesCount | numeric |  |  
action_result.data.\*.keywordsRetainingParentCategory | string |  |  
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |  
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric |  |  
action_result.message | string |  |   Message: Category ips removed 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create destination group'
Create destination group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Destination IP group name | string | 
**type** |  required  | Destination IP group type (i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs) | string | 
**addresses** |  optional  | Comma seperated string of destination IP addresses, FQDNs, or wildcard FQDNs added to the group | string | 
**description** |  optional  | Additional information about the destination IP group. | string | 
**ip_categories** |  optional  | Destination IP address URL categories | string | 
**countries** |  optional  | Destination IP address countries. You can identify destinations based on the location of a server. | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.countries | string |  |  
action_result.parameter.ip_categories | string |  |  
action_result.parameter.description | string |  |  
action_result.parameter.addresses | string |  |  
action_result.parameter.type | string |  |  
action_result.parameter.name | string |  |  
action_result.data.\*.id | numeric |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.type | string |  |   DSTN_IP  DSTN_FQDN  DSTN_DOMAIN  DSTN_OTHER 
action_result.data.\*.addresses | string |  |   192.168.1.1 
action_result.data.\*.countries | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.ipCategories | string |  |   TRADING_BROKARAGE_INSURANCE 
action_result.data.\*.isNonEditable | boolean |  |   True  False 
action_result.data.\*.creatorContext | string |  |  
action_result.summary | string |  |  
action_result.summary.message | string |  |   test User removed from group 
action_result.message | string |  |   test User removed from group 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list destination group'
List destination group

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_group_ids** |  optional  | A comma-separated list of unique identifiers for the IP destination groups | string | 
**exclude_type** |  optional  | The IP group type to be excluded from the results | string | 
**category_type** |  optional  | Comma seperated list of IP group types to be filtered from results. This argument is only supported when the 'lite' argument is set to True | string | 
**limit** |  optional  | Limit of the results to be retrieved | numeric | 
**include_ipv6** |  optional  | Retrieve IPv6 destination groups | boolean | 
**lite** |  optional  | Whether to retrieve only limited information of IP destination groups. Includes ID, name and type of the IP destination groups | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.lite | boolean |  |  
action_result.parameter.include_ipv6 | boolean |  |  
action_result.parameter.limit | numeric |  |  
action_result.parameter.category_type | string |  |  
action_result.parameter.exclude_type | string |  |  
action_result.parameter.ip_group_ids | string |  |  
action_result.data.\*.id | numeric |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.type | string |  |   DSTN_IP  DSTN_FQDN  DSTN_DOMAIN  DSTN_OTHER 
action_result.data.\*.addresses | string |  |   192.168.1.1 
action_result.data.\*.countries | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.ipCategories | string |  |   TRADING_BROKARAGE_INSURANCE 
action_result.data.\*.isNonEditable | boolean |  |   True  False 
action_result.data.\*.creatorContext | string |  |  
action_result.summary | string |  |  
action_result.summary.message | string |  |   Retreived Destination Groups 
action_result.message | string |  |   Retreived Destination Groups 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'edit destination group'
Edit destination group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_group_id** |  required  | The unique identifier for the IP destination group | numeric | 
**name** |  optional  | Destination IP group name | string | 
**addresses** |  optional  | Comma seperated string of destination IP addresses, FQDNs, or wildcard FQDNs added to the group | string | 
**description** |  optional  | Additional information about the destination IP group. | string | 
**ip_categories** |  optional  | Destination IP address URL categories | string | 
**countries** |  optional  | Destination IP address countries. You can identify destinations based on the location of a server. | string | 
**is_non_editable** |  optional  | If set to true, the destination IP address group is non-editable. This field is applicable only to predefined IP address groups, which cannot be modified | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.is_non_editable | boolean |  |  
action_result.parameter.countries | string |  |  
action_result.parameter.ip_categories | string |  |  
action_result.parameter.description | string |  |  
action_result.parameter.addresses | string |  |  
action_result.parameter.name | string |  |  
action_result.parameter.ip_group_id | numeric |  |  
action_result.data.\*.id | numeric |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.type | string |  |   DSTN_IP  DSTN_FQDN  DSTN_DOMAIN  DSTN_OTHER 
action_result.data.\*.addresses | string |  |   192.168.1.1 
action_result.data.\*.countries | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.ipCategories | string |  |   TRADING_BROKARAGE_INSURANCE 
action_result.data.\*.isNonEditable | boolean |  |   True  False 
action_result.data.\*.creatorContext | string |  |  
action_result.summary | string |  |  
action_result.summary.message | string |  |   Destination group edited 
action_result.message | string |  |   Destination group edited 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'delete destination group'
Delete destination group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_group_ids** |  optional  | A comma-separated list of unique identifiers for the IP destination groups | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.ip_group_ids | string |  |  
action_result.data.\*.ip_group_ids | string |  |  
action_result.summary | string |  |  
action_result.summary.message | string |  |   Destination group deleted 
action_result.message | string |  |   Destination group deleted 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get departments'
Get a list of departments

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  optional  | Filter by department name | string | 
**page** |  optional  | Specifies the page offset | numeric | 
**pageSize** |  optional  | Specifies the page size | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.pageSize | string |  |  
action_result.parameter.page | string |  |  
action_result.parameter.name | string |  |  
action_result.data.\*.id | numeric |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.isNonEditable | boolean |  |  
action_result.summary | string |  |  
action_result.summary.message | string |  |   Departments Retrieved 
action_result.summary.total_deparments | numeric |  |   97 
action_result.message | string |  |   Departments Retrieved 
summary.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get category details'
Get the urls and keywords of a category

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**category_ids** |  optional  | Comma seperated string of category id's to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   test success  test failed 
action_result.parameter.category_ids | string |  |   CUSTOM_001, CUSTOM_002 
action_result.data.\*.configuredName | string |  |   test Test-Caution 
action_result.data.\*.customCategory | boolean |  |   True  False 
action_result.data.\*.keywords | string |  |  
action_result.data.\*.urls | string |  |  
action_result.data.\*.customIpRangesCount | numeric |  |   0 
action_result.data.\*.customUrlsCount | numeric |  |   0 
action_result.data.\*.dbCategorizedUrls | string |  |   test 6.5.3.2.4 
action_result.data.\*.description | string |  |   test OTHER_RESTRICTED_WEBSITE_DESC 
action_result.data.\*.editable | boolean |  |   True  False 
action_result.data.\*.id | string |  `zscaler url category`  |   test OTHER_RESTRICTED_WEBSITE 
action_result.data.\*.ipRangesRetainingParentCategoryCount | numeric |  |   0 
action_result.data.\*.scopes.\*.Type | string |  |   test ORGANIZATION 
action_result.data.\*.type | string |  |   test URL_CATEGORY 
action_result.data.\*.urlsRetainingParentCategoryCount | numeric |  |   0 
action_result.data.\*.val | numeric |  |   1 
action_result.summary.total_categories | numeric |  |   97 
action_result.message | string |  |   Category details recieved 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 