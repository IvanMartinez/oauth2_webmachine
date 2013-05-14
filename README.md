# oauth2_webmachine

This is a sample implementation of an OAuth 2 server using Webmachine. It's intended to be used as a reference or starting point for other implementations. *It's not secure as it is*, mainly because it uses HTTP clear-text communication. 

## OAuth 2 implementation

This server is intendend to comply with this specification:

http://tools.ietf.org/html/rfc6749

Below are some considerations and clarifications about this implementaton, referred to the section number in the specification:

2.3. Client Authentication

Both the use of HTTP Basic authentication [RFC2617], or client_id and client_secret parameters, are supported. If a client wrongly uses both in the same request, only the HTTP Basic authentication is considered.

3.1. Authorization Endpoint
3.1.2.2. Registration Requirements

Registering multiple redirection endpoints for a client is not allowed.

3.3. Access Token Scope

Scopes may be separated by "+" and/or "%20" characters. If the requested scope is a subset of the registered scope, the response returns the requested scope. If the request contains no scope parameter, the response returns the registered scope. If the registered scope is empty, and the request contains no scope parameter or its value is empty, the response returns an empty scope value.

4.1. Authorization Code Grant
4.1.2.1. Error Response

The following errors may occur before the existence of a redirection URI is confirmed, so they are not forwarded to any URI. They are the direct response to the request.

1. HTTP 400 Bad Request. The request has no "client_id" parameter.
1. HTTP 401 Unauthorized. The value of the "client_id" parameter doesn't match the id of any registered client, or the value of the "redirect_uri" parameter doesn't match the registered redirection URI of the client.
1. HTTP 403 Forbidden. The value of the "client_id" parameter matches the id of a registered client, but this doesn't have a registered redirection URI. The validity of the redirection URI is not checked, this should be done during client registration.

Any other error or successful response is forwarded to the registered redirection URI of the client with a HTTP 302 response, as explained in the specification.

5.2. Error Response

- invalid_request: If the request has a repeated parameter, the value of the first occurrence will be taken without necessarily producing an error. Such is the behaviour of
Webmachine's wrq:get_qs_value/2 function. Using more than one authenticating mechanism doesn't necessarily produce an error either, see point 2.3. above.

- invalid_client: This error is returned in a HTTP 401 response, with authenticate realm "oauth2_webmachine". The realm is defined in "oauth2_wrq.hrl" file.

- unsupported_grant_type: Since this implementation uses a different URL path for each grant type, issuing a wrong grant_type value for a certain path (i.e. http:/localhost:8000//client_token?grant_type=password) results in a unsupponted_grant_type error. In cases like this the error doesn't mean that the grant type isn't supported at all, only that it's being sent to the wrong URL.

## Feedback

Please open a Github issue or Pull Request if you:

- Find any security issue, besides the intended use of clear-text HTTP.
- Find any disagreement with the mentioned OAuth 2 specification.
- Have any comment or suggestion.

Your feedback is greatly appreciated.
