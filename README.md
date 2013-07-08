# oauth2_webmachine

This is a sample implementation of an OAuth 2 server using Webmachine. It's intended to be used as a reference or starting point for other implementations. *It's not secure as it is*, mainly because it uses HTTP clear-text communication. 

## Quickstart

Compile and execute with

    $ make
    $ ./start.sh

## Testing

Execute unit tests with 

    $ rebar eunit skip_deps=true

In order to make the tests below work, a sample client and resource owner must be created. Execute the following commands in the shell of the Erlang instance running the server:

    > oauth2_ets_backend:add_client(<<"Client1">>, <<"Secret1">>, <<"http://client.uri">>, [<<"root.a.*">>, <<"root.x.y">>]).
    > oauth2_ets_backend:add_resowner(<<"User1">>, <<"Password1">>, [<<"root1.z">>, <<"root2.*">>]).

The tests use [curl](http://curl.haxx.se/) to send requests. Both http GET and POST methods are supported, so the following two are equivalent:

    $ curl -v -X POST http://127.0.0.1:8000/owner_token -d "grant_type=password&username=User1&password=Password1"
    $ curl -v -X GET "http://127.0.0.1:8000/owner_token?grant_type=password&username=User1&password=Password1"

### Authorization Code Grant

Send a code request with

    $ curl -v -X POST http://127.0.0.1:8000/authorization_code -d "response_type=code&client_id=Client1&redirect_uri=http://client.uri&scope=root.a.b root.x.y&state=foo"

The server responds with a HTML form for resource owner authentication. Notice the value of the request_id field

    <input type="hidden" name="request_id" value="mqWsdDvojGKTFegAiY5a9wH3RRjD0Ump">

Use that value to create and send a response to the form, like

    $ curl -v -X POST http://127.0.0.1:8000/authorization_code_form -d "request_id=mqWsdDvojGKTFegAiY5a9wH3RRjD0Ump&username=User1&password=Password1"

The server responds with a HTTP 302 status, and the authorization code is in the Location field of the header

    Location: http://client.uri?code=cWBQ1GF7sK05hX8j3dlF76YPNmztZEgb&state=foo

Use that code to request an access token

    $ curl -v -X POST http://127.0.0.1:8000/access_token -d "grant_type=authorization_code&client_id=Client1&client_secret=Secret1&redirect_uri=http://client.uri&code=cWBQ1GF7sK05hX8j3dlF76YPNmztZEgb"

Another way of testing this flow is opening test/authorization_code_test.html with a browser. The first form will ask for the values of the fields of the first request, and from there the flow will be handled by the browser. If nobody is listening at the redirection URI the flow will end in a 404 Not Found error, but the code should be visible in the URI of the browser

    http://client.uri?code=MWOqlwshyblAHm3AvNPFf2c96tAtZYsG&state=foo

### Implicit Grant

Send a token request with

    $ curl -v -X POST http://127.0.0.1:8000/authorization_token -d "response_type=token&client_id=AnyClient&redirect_uri=http://anyclient.uri&scope=root1.z root2.b&state=foo"

The server responds with a HTML form for resource owner authentication. Notice the value of the request_id field

    <input type="hidden" name="request_id" value="mqWsdDvojGKTFegAiY5a9wH3RRjD0Ump">

Use that value to create and send a response to the form, like

    $ curl -v -X POST http://127.0.0.1:8000/authorization_token_form -d "request_id=mqWsdDvojGKTFegAiY5a9wH3RRjD0Ump&username=User1&password=Password1"

The server responds with a HTTP 302 status, and the access token parameters are in the Location field of the header

    Location: http://anyclient.uri?access_token=bHcbA5Q8OHlZyODcR4JwO7JOrD8bto2K&token_type=bearer&expires_in=3600&scope=root1.z root2.b&state=foo

Another way of testing this flow is opening test/implicit_grant_test.html with a browser. The first form will ask for the values of the fields of the first request, and from there the flow will be handled by the browser. If nobody is listening at the redirection URI the flow will end in a 404 Not Found error, but the access token parameters should be visible in the URI of the browser

    http://anyclient.uri?access_token=67gPEezhJAjbeq0VvgoaURi8HkhGWlOx&token_type=bearer&expires_in=3600&scope=root1.z%20root2.b&state=foo


### Resource Owner Password Credentials Grant

Send an access token request with

    $ curl -v -X POST http://127.0.0.1:8000/owner_token -d "grant_type=password&username=User1&password=Password1&scope=root1.z+root2.c.d"

### Client Credentials Grant

Send an access token request with

    $ curl -v -X POST http://127.0.0.1:8000/client_token -d "grant_type=client_credentials&client_id=Client1&client_secret=Secret1&scope=root.a.c"

## OAuth 2 implementation

This server is intended to comply with this specification:

http://tools.ietf.org/html/rfc6749

Below are some considerations and clarifications about this implementaton, referred to the section number in the specification:

2.3. Client Authentication

Both the use of HTTP Basic authentication [RFC2617], or client_id and client_secret parameters, are supported. If a client wrongly uses both in the same request, only the HTTP Basic authentication is considered.

3.1. Authorization Endpoint
3.1.2.2. Registration Requirements

Registering multiple redirection endpoints for a client is not allowed.

3.3. Access Token Scope

Scopes may be separated by "+" and/or "%20" characters. If the requested scope is a subset of the registered scope, the response returns the requested scope. If the request contains no scope parameter, the response returns the registered scope. If the registered scope is empty, and the request contains no scope parameter or its value is empty, the response returns an empty scope value.

For more information about scope validation, see https://github.com/kivra/oauth2 README.md file.

4.1. Authorization Code Grant
4.1.2.1. Error Response

The following errors may occur before the existence of a redirection URI is confirmed, so they are not forwarded to any URI. They are the direct response to the request.

- HTTP 400 Bad Request. If returned before the authentication form is presented, the request has no "client_id" parameter. If returned after the authentication form is presented, the form is missing a required field (request_id, username or password).
- HTTP 401 Unauthorized. The value of the "client_id" parameter doesn't match the id of any registered client, or the value of the "redirect_uri" parameter doesn't match the registered redirection URI of the client.
- HTTP 403 Forbidden. The value of the "client_id" parameter matches the id of a registered client, but this doesn't have a registered redirection URI. The validity of the redirection URI is not checked, this should be done during client registration.
- HTTP 408 Request timeout. The server couldn't find stored data of the initial request. This is probably because the resource owner took too long to answer the authentication form.

Any other error or successful response is forwarded to the registered redirection URI of the client with a HTTP 302 response, as explained in the specification.

4.1.3. Access Token Request

The redirect_uri parameter is always required, even if it wasn't included in authorization request.

5.2. Error Response

- invalid_request: If the request has a repeated parameter, the value of the first occurrence will be taken without necessarily producing an error. Such is the behaviour of
Webmachine's wrq:get_qs_value/2 function. Using more than one authenticating mechanism doesn't necessarily produce an error either, see point 2.3. above.

- invalid_client: This error is returned in a HTTP 401 response, with authenticate realm "oauth2_webmachine". The realm is defined in "oauth2_wrq.erl" file.

- unsupported_grant_type: Since this implementation uses a different URL path for each grant type, issuing a wrong grant_type value for a certain path (i.e. http:/localhost:8000/client_token?grant_type=password) results in a unsupponted_grant_type error. In cases like this the error doesn't mean that the grant type isn't supported at all, only that it's being sent to the wrong URL.

## Feedback

Please open a Github issue or Pull Request if you:

- Find any security issue, besides the intended use of clear-text HTTP.
- Find any disagreement with the mentioned OAuth 2 specification.
- Have any comment or suggestion.

Your feedback is greatly appreciated.
