# security_trm.js
Token Resource Metering - applying proof of work (PoW) concepts to disrupt robotic attacks against a web application.

##### Purpose #####
Used to generate Proof of Work (PoW) tokens for server-side validation

Prevents bots that aren't javascript-capable, slows down bots that are

Created by Sean Whiteley (sean@appsec.org.uk)

Uses a JavaScript-optimised version of the SHA-1 Reference Implementation (not perfect, by any means)

See http://dx.doi.org/10.6028/NIST.FIPS.180-4
#####


##### What are these tokens and what do they do? #####
1. Randomly generate a configurable-length word

2. Check if that word's sha1 hash matches criteria

3. If match, the client's token is that word - put it in a hidden field ready for the user to submit / POST

4. If no match, restart at step 1


The "criteria" is usually "first X bits are equal to zero". This allows you to control the compute requirement dynamically and speed up or slow down form submissions as required.
#####


##### How much compute power does it take to meet the criteria? #####
On a typical laptop or smartphone, it generally takes under a second to create a token even when the criteria is "first 16 bits equal to zero". You can use this is a baseline and tweak as necessary.
#####


##### Functional Requirements #####
JavaScript must be enabled

The web form's submit button must have id="submitWithSha1"

The web form must include a hidden text field with id="sha1Str", max length 40

The page's encoding type must be set to UTF-8 (meta charset tag & Content-Type header)
#####


##### Functional Recommendations #####
Modify to use async functions so that page-load isn't stalled while tokens are generated - I plan on doing this but as of 01/10/2017 this is just a proof of concept.
#####


##### Security Recommendations #####
If you distribute this script file via a CDN, consider using Subresource Integrity (https://www.w3.org/TR/SRI/)

Server should check for multiple repeat tokens from the same client

Server should check for empty sha1Str BEFORE performing validation, potential DoS otherwise

Errors should trigger a redirect to the "javascript-disabled" page or equivalent

If you're using a pre-populated value for sha1Str, check that it doesn't meet the token criteria ;)
#####
