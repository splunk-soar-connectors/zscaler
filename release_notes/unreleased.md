**Unreleased**

* Validate numeric user and group identifiers and encode all caller-controlled ZIA path segments.
* Escape file hashes before embedding them in custom-view JavaScript.
* Activate staged ZIA policy and destination-group changes before reporting success.
* Preserve destination-group non-editable state when the edit parameter is omitted.
* Require HTTPS when transmitting sandbox API tokens to the legacy submission endpoint.
* Cap server-directed rate-limit waits at 60 seconds and reject malformed values.
* Serialize allowlist read-modify-write actions to prevent concurrent update loss.
