Below points are considered for providing the **URL Category** parameter value.

- Entire URL category string has to be mentioned in block letters

- The most child category on UI has to be passed as the URL category parameter value to the action

- From the URL category value on UI, every space has to be replaced by an underscore '\_' before
  passing it in the action's parameter value

  - For example, **Alternate Lifestyle** on UI becomes **ALTERNATE_LIFESTYLE**

- When you specify a **url_category** , you can give it either the name you created or the ID
  which is assigned to it from Zscaler. The search will first search for the name, as opposed to
  the ID. So if you create a category **phantom-block** , you could use either **phantom-block**
  or **CUSTOM\_\*\*** . The name for these is case sensitive.

The following are considered for providing the **URL** parameter value.

- The comma-separated values of **URL** should correctly be given e.g. test.com,test1.com else the
  Phantom framework's parameter validator will return the error mentioning **Exception occurred:
  string index out of range** .

Configure and set up permissions for the **lookup_url** action

- Login to Zscaler UI using the Administrator credentials.
- Once logged in, go to **Administration -> Role Management** section.
- Click on the **Edit** icon beside the role that your account uses to configure the test
  connectivity.
- Go to the **Functional Scope** section, enable **Security** if disabled, and save it.

The above steps would help run the Lookup URL action as expected.

The Sandbox Submission API requires a separate API key and uses a different host
(csbapi.[zscaler-cloud-name]). For the **submit_file** action, the **sandbox_base_url** and
**sandbox_api_token** asset configuration parameters should be configured. These two asset
parameters won't affect test_connectivity. Follow the below steps to fetch these credentials for the
**submit_file** action

- Log in to the ZIA Admin Portal using your **admin** credentials.
- Once logged in, go to **Administration -> Cloud Service API Key Management** section. In order
  to view the Cloud Service API Key Management page, the admin must be assigned an admin role.
- For the Cloud Sandbox Submission API used in this action, the base URL and token are displayed
  on the **Sandbox Submission API Token** tab.
- The base URL and token displayed here can be configured in the asset parameters in
  **sandbox_base_url** and **sandbox_api_token** parameters respectively and will be used for the
  submit_file action.

The above steps would help run the Submit File action as expected.

**NOTE:** This action would work according to the API behavior

Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Zscaler server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |
