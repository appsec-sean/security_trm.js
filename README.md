# security_trm.js
Token Resource Metering - applying proof of work (PoW) concepts to disrupt robotic attacks against a web application.

Used to generate Proof of Work (PoW) tokens for server-side validation
Prevents bots that aren't javascript-capable, slows down bots that are
Created by Sean Whiteley (sean@appsec.org.uk)
Uses a JavaScript-optimised version of the SHA-1 Reference Implementation (not perfect, by any means)
See http://dx.doi.org/10.6028/NIST.FIPS.180-4

Functional Requirements:
JavaScript must be enabled
The web form's submit button must have id="submitWithSha1"
The web form must include a hidden text field with id="sha1Str", max length 40
The page's encoding type must be set to UTF-8 (<meta charset="utf-8"> & Content-Type header)

Functional Recommendations:
Load this script after all other scripts so that it doesn't disrupt user interaction

Security Recommendations:
If you distribute this script file via a CDN, consider using Subresource Integrity (https://www.w3.org/TR/SRI/)
Server should check for multiple repeat tokens from the same client
Server should check for empty sha1Str BEFORE performing validation, potential DoS otherwise
Errors should trigger a redirect to the "javascript-disabled" page or equivalent
If you're using a pre-populated value for sha1Str, check that it doesn't meet the token criteria ;)
