# oauth2_webmachine

This is a sample implementation of an OAuth 2 server using Webmachine. It's intended to be used as a reference or starting point for other implementations. *It's not secure as it is*, mainly because it uses HTTP clear-text communication. 

## Quickstart

Compile and execute with

    $ make
    $ ./start.sh

## Testing

Execute unit tests with 

    $ rebar eunit skip_deps=true

### Resource Owner Password Credentials Grant

Add a user in the command shell of the Erlang instance running the server with

    > oauth2_ets_backend:add_user(<<"User1">>, <<"Password1">>, [<<"root.a.*">>, <<"root.x.y">>]).

Use curl to send requests in the system command shell like

    $ curl -v -X POST http://127.0.0.1:8000/owner_token -d "grant_type=password&username=User1&password=Password1&scope=root.a.b+root.x.y"
    $ curl -v -X GET "http://127.0.0.1:8000/owner_token?grant_type=password&username=User1&password=Password1&scope=root.a.b+root.x.y"

### Client Credentials Grant

Add a client in the command shell of the Erlang instance running the server with

    > oauth2_ets_backend:add_client(<<"Client1">>, <<"Secret1">>, <<"Uri">>, [<<"root.a.*">>, <<"root.x.y">>]).

Use curl to send requests in the system command shell like

    $ curl -v -X POST http://127.0.0.1:8000/client_token -d "grant_type=client_credentials&client_id=Client1&client_secret=Secret1&scope=root.a.b root.x.y"
    $ curl -v -X GET "http://127.0.0.1:8000/client_token?grant_type=client_credentials&client_id=Client1&client_secret=Secret1&scope=root.a.b+root.x.y"

## OAuth 2 implementation

This server is intendend to comply with this specification:

http://tools.ietf.org/html/rfc6749

Below are some considerations and clarifications about this implementaton, referred to the section number in the specification:

2.3. Client Authentication

Both the use of HTTP Basic authentication [RFC2617], or client_id and client_secret parameters, are supported. If a client wrongly uses both in the same request, only the HTTP Basic authentication is considered.

3.3. Access Token Scope

Scopes may be separated by "+" and/or "%20" characters. If the requested scope is a subset of the registered scope, the response returns the requested scope. If the request contains no scope parameter, the response returns the registered scope. If the registered scope is empty, and the request contains no scope parameter or its value is empty, the response returns an empty scope value.

For more information about scope validation, see https://github.com/IvanMartinez/oauth2 README.md file.

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
