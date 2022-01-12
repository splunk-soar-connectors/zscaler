[comment]: # "Auto-generated SOAR connector documentation"
# Zscaler

Publisher: Splunk  
Connector Version: 2\.1\.6  
Product Vendor: Zscaler  
Product Name: Zscaler  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app implements containment and investigative actions on Zscaler

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2017-2021 Splunk Inc."
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Zscaler asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL \(e\.g\. https\://admin\.zscaler\_instance\.net\)
**api\_key** |  required  | password | API Key
**username** |  required  | string | Username
**password** |  required  | password | Password

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
**file\_hash** |  required  | The md5 file hash | string |  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash | string |  `md5` 
action\_result\.data\.\*\.Full Details\.Classification\.Category | string | 
action\_result\.data\.\*\.Full Details\.Classification\.DetectedMalware | string | 
action\_result\.data\.\*\.Full Details\.Classification\.Score | numeric | 
action\_result\.data\.\*\.Full Details\.Classification\.Type | string | 
action\_result\.data\.\*\.Full Details\.FileProperties\.DigitalCerificate | string | 
action\_result\.data\.\*\.Full Details\.FileProperties\.FileSize | numeric | 
action\_result\.data\.\*\.Full Details\.FileProperties\.FileType | string | 
action\_result\.data\.\*\.Full Details\.FileProperties\.Issuer | string | 
action\_result\.data\.\*\.Full Details\.FileProperties\.MD5 | string |  `md5` 
action\_result\.data\.\*\.Full Details\.FileProperties\.RootCA | string | 
action\_result\.data\.\*\.Full Details\.FileProperties\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.Full Details\.FileProperties\.SSDeep | string | 
action\_result\.data\.\*\.Full Details\.FileProperties\.Sha256 | string |  `sha256` 
action\_result\.data\.\*\.Full Details\.Origin\.Country | string | 
action\_result\.data\.\*\.Full Details\.Origin\.Language | string | 
action\_result\.data\.\*\.Full Details\.Origin\.Risk | string | 
action\_result\.data\.\*\.Full Details\.Summary\.Category | string | 
action\_result\.data\.\*\.Full Details\.Summary\.Duration | numeric | 
action\_result\.data\.\*\.Full Details\.Summary\.FileType | string | 
action\_result\.data\.\*\.Full Details\.Summary\.StartTime | numeric | 
action\_result\.data\.\*\.Full Details\.Summary\.Status | string | 
action\_result\.data\.\*\.Full Details\.SystemSummary\.\*\.Risk | string | 
action\_result\.data\.\*\.Full Details\.SystemSummary\.\*\.Signature | string | 
action\_result\.data\.\*\.Full Details\.SystemSummary\.\*\.SignatureSources | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list url categories'
List all URL categories

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.customUrlsCount | numeric | 
action\_result\.data\.\*\.urlsRetainingParentCategoryCount | numeric | 
action\_result\.data\.\*\.scopes\.\*\.Type | string | 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.editable | boolean | 
action\_result\.data\.\*\.id | string |  `zscaler url category` 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.total\_url\_categories | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block ip'
Block an IP

Type: **contain**  
Read only: **False**

If a <b>url\_category</b> is specified, it will add the IP\(s\) as a rule to that category\. If it is left blank, it will instead add the IP\(s\) to the global blocklist\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url\_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block url'
Block a URL

Type: **contain**  
Read only: **False**

If a <b>url\_category</b> is specified, it will add the URL\(s\) as a rule to that category\. If it is left blank, it will instead add the URL\(s\) to the global blocklist\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 
**url\_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain`  `url list` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.editable | boolean | 
action\_result\.data\.\*\.customUrlsCount | numeric | 
action\_result\.data\.\*\.urlsRetainingParentCategoryCount | numeric | 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock ip'
Unblock an IP

Type: **correct**  
Read only: **False**

If a <b>url\_category</b> is specified, it will remove the IP\(s\) from that category\. If it is left blank, it will instead remove the IP\(s\) from the global blocklist\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url\_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock url'
Unblock a URL

Type: **correct**  
Read only: **False**

If a <b>url\_category</b> is specified, it will remove the URL\(s\) from that category\. If it is left blank, it will instead remove the URL\(s\) from the global blocklist\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 
**url\_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain`  `url list` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.editable | boolean | 
action\_result\.data\.\*\.customUrlsCount | numeric | 
action\_result\.data\.\*\.urlsRetainingParentCategoryCount | numeric | 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'allow ip'
Add an IP address to the allowlist

Type: **contain**  
Read only: **False**

If a <b>url\_category</b> is specified, it will add the IP\(s\) as a rule to that category\. If it is left blank, it will instead add this IP\(s\) to the global allowlist\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url\_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'allow url'
Add a URL to the allowed list

Type: **contain**  
Read only: **False**

If a <b>url\_category</b> is specified, it will add the URL\(s\) as a rule to that category\. If it is left blank, it will instead add the URL\(s\) to the global allowed list\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 
**url\_category** |  optional  | Add to this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain`  `url list` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.editable | boolean | 
action\_result\.data\.\*\.customUrlsCount | numeric | 
action\_result\.data\.\*\.urlsRetainingParentCategoryCount | numeric | 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unallow ip'
Remove an IP address from the allowlist

Type: **correct**  
Read only: **False**

If a <b>url\_category</b> is specified, it will remove the IP\(s\) from that category\. If it is left blank, it will instead remove the IP\(s\) from the global allowlist\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 
**url\_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unallow url'
Remove a URL from the allowed list

Type: **correct**  
Read only: **False**

If a <b>url\_category</b> is specified, it will remove the URL\(s\) from that category\. If it is left blank, it will instead remove the URL\(s\) from the global allowed list\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 
**url\_category** |  optional  | Remove from this category | string |  `zscaler url category` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain`  `url list` 
action\_result\.parameter\.url\_category | string |  `zscaler url category` 
action\_result\.data\.\*\.configuredName | string | 
action\_result\.data\.\*\.customCategory | boolean | 
action\_result\.data\.\*\.dbCategorizedUrls | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.val | numeric | 
action\_result\.summary\.ignored | string | 
action\_result\.summary\.updated | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Lookup the categories related to an IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | A list of IPs | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.blocklisted | boolean | 
action\_result\.data\.\*\.url | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.urlClassifications | string | 
action\_result\.data\.\*\.urlClassificationsWithSecurityAlert | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup url'
Lookup the categories related to a URL

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | A list of URLs | string |  `url`  `domain`  `url list` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url`  `domain`  `url list` 
action\_result\.data\.\*\.blocklisted | boolean | 
action\_result\.data\.\*\.url | string |  `url`  `domain`  `url list` 
action\_result\.data\.\*\.urlClassifications | string | 
action\_result\.data\.\*\.urlClassificationsWithSecurityAlert | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 

## action: 'get admin users'
Retrieve Zscaler portal administrative users and their roles

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.loginName | string | 
action\_result\.data\.\*\.userName | string | 
action\_result\.data\.\*\.email | string | 
action\_result\.data\.\*\.role\.id | string | 
action\_result\.data\.\*\.role\.name | string | 
action\_result\.data\.\*\.role\.extensions\.adminRank | string | 
action\_result\.data\.\*\.role\.extensions\.roleType | string | 
action\_result\.data\.\*\.role\.adminScopeType | string | 
action\_result\.data\.\*\.role\.isNonEditable | boolean | 
action\_result\.data\.\*\.role\.isPasswordLoginAllowed | boolean | 
action\_result\.data\.\*\.role\.pwdLastModifiedTime | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
