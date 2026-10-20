# JSON delivery report

## T100 message class

Create SE91 class Z\_OAUTH\_REST and transport it with the report. Diagnostics and output labels come from T100 through MESSAGE ... INTO; the source has no literal UI messages.

|No.|T100 text|No.|T100 text|
|-|-|-|-|
|001|Destination \&1 unavailable.|014|Payload exceeds 1 MiB.|
|002|HTTP transport failed; subrc \&1.|015|OAuth field \&1 is missing/invalid.|
|003|Source reference is initial.|016|OAuth token type is not Bearer.|
|004|Could not dereference source data.|017|Access token or expiry is invalid.|
|005|JSON depth limit \&1 exceeded.|018|Invalid Bearer-token character.|
|006|Cannot read component \&1.|019|Token endpoint HTTP \&1: \&2.|
|007|Cannot access source table.|020|Token expiry calculation failed.|
|008|Object references unsupported.|021|API HTTP \&1: \&2.|
|009|Unsupported ABAP type \&1.|022|Retry-After: \&1.|
|010|Unsupported JSON control character.|023|Delivery error:|
|011|Invalid JSON number format.|024|HTTP status: \&1|
|012|JSON serialization failed: \&1.|025|Response body:|
|013|UTF-8 conversion failed: \&1.|||

## SM59 setup

Create two HTTPS Type G destinations; trust their certificates in STRUST:

* Z\_OAUTH\_TOKEN\_SERVER: path prefix /oauth/token; set Basic logon user/password to the client ID/secret.
* Z\_API\_EVENTS\_OUTBOUND: path prefix /api/events; the report sets Bearer authentication.

Hosts, paths, and credentials stay outside the source. Verify Basic-auth encoding with the provider if credentials contain reserved characters.

## Behavior and limits

RTTS maps structures to lowercase-key objects and internal tables to arrays. Numeric values are normalized for both comma-decimal user formats (`sy-dcpfm` X and Y). JSON is converted to UTF-8 before the 1 MiB byte check. Tokens are cached per destination and refreshed 30 seconds early. A 401 clears the cache for the next send; 429 reports Retry-After without retrying.

The focused token-response reader decodes all simple JSON escapes and printable-ASCII `\\uXXXX` escapes. The recognized escaped controls are decoded and then rejected by OAuth token validation; other control and non-ASCII Unicode escapes are rejected as invalid OAuth field data. This is not a general JSON parser. Bearer characters are checked with CN and '=' padding must be trailing. Object references and unsupported types return errors.  Two ABAP Unit Tests are fully implemented to validate nested/lowercase JSON structure processing and robust string escaping. These are structured and to be executed upon activation on the target NetWeaver 7.31 environment.

