**Unreleased**
* Block and lookup actions now account for ZIA allowlist entries that override the advanced-threat denylist.
* Group membership updates now fetch the user immediately before writing and compare existing memberships by group ID.
* URL list actions now convert internationalized hostnames to IDNA2008 A-labels before sending them to ZIA.
* URL category actions now use incremental list updates that preserve concurrent entries and existing keyword configuration.
* The get departments action now encodes its search and pagination query parameters through the HTTP client.
* Authentication now returns a controlled error when the ZIA response omits its required session cookie.
* Unblock and unallow actions now remove only shared-list entries recorded as added by the current connector asset.
* Unexpected scalar JSON and malformed rate-limit response bodies now return controlled action errors.
* Unparseable Retry-After values now preserve the original rate-limit failure instead of being treated as success.
* URL category updates and user listing now inherit the connector's finite request timeout.
