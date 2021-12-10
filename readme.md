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

The Sandbox Submission API requires a separate API key and uses a different host (csbapi.[zscaler-cloud-name]). Follow the below steps to fetch the credentials for the **submit_file** action

-   Log in to the ZIA Admin Portal using your **admin** credentials.
-   Once logged in, go to **Administration -> Cloud Service API Key Management** section. In order to view the Cloud Service API Key Management page, the admin must be assigned an admin role.
-   For the Cloud Sandbox Submission API used in this action, the base URL and token are displayed on the **Sandbox Submission API Token** tab.
-   The base URL and token displayed here can be used as **sandbox_base_url** and **api_token** parameters for the action respectively.

The above steps would help run the Submit File action as expected.
