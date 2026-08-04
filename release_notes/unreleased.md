**Unreleased**
* Block and lookup actions now account for ZIA allowlist entries that override the advanced-threat denylist.
* Group membership updates now fetch the user immediately before writing and compare existing memberships by group ID.
* URL list actions now convert internationalized hostnames to IDNA2008 A-labels before sending them to ZIA.
* URL category actions now use incremental list updates that preserve concurrent entries and existing keyword configuration.
