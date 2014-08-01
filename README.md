# oauth2_webmachine

This is a sample implementation of an OAuth 2 server using Webmachine. It's intended to be used as a reference or starting point for other implementations. **Don't use it in a production enviroment as it is**, it hasn't been properly tested or audited for that. The authors take no responsability for any damage or issue resulting from using this implementation. Please read the LICENSE file.

It certainly **is not secure** because:

- It uses clear-text communication. If you want to enable encryption, read the [webmachine wiki](https://github.com/basho/webmachine/wiki) or use a reverse-proxy like [Nginx](http://wiki.nginx.org/Main).
- Generated authorization codes and tokens never expire. You should implement this in your server.

## Quickstart

Compile and execute with

    $ make
    $ ./start.sh

## Testing

In order to make the tests below work, a sample client and resource owner must be created. Execute the following commands in the shell of the Erlang instance running the server:

    > oauth2_ets_backend:add_client(<<"Client1">>, <<"Secret1">>, <<"http://client.uri">>, [<<"root.a.*">>, <<"root.x.y">>]).
    > oauth2_ets_backend:add_resowner(<<"User1">>, <<"Password1">>, [<<"root1.z">>, <<"root2.*">>]).

With the server running, execute unit tests in another shell with

    $ make test

The tests below use [curl](http://curl.haxx.se/) to send requests.

### Authorization Code Grant

Open the following URL in a browser

    (http://127.0.0.1:8000/authorization_code?response_type=code&client_id=Client1&redirect_uri=http://client.uri&scope=root1.z+root2.a&state=foo)

Enter ```User1``` in user and ```Password1``` in password. Click Accept. The browser should be redirected to a URL that contains the authorization code in a parameter like

    http://client.uri/?code=Nnm8FdT3OJE3cBWCGBipCU1mjssjTuPo&state=foo

Alternatively, you can use curl to request a code with

    $ curl -v -X POST http://127.0.0.1:8000/authorization_code -d "response_type=code&client_id=Client1&redirect_uri=http://client.uri&scope=root1.z+root2.a&state=foo&username=User1&password=Password1"

The server responds with a HTTP 302 status, and the authorization code is in the Location field of the header

    Location: http://client.uri?code=cWBQ1GF7sK05hX8j3dlF76YPNmztZEgb&state=foo

Use that code to request an access token

    $ curl -v -X POST http://127.0.0.1:8000/access_token -d "grant_type=authorization_code&client_id=Client1&client_secret=Secret1&redirect_uri=http://client.uri&code=cWBQ1GF7sK05hX8j3dlF76YPNmztZEgb"

Another way of testing this flow is opening test/authorization_code_test.html with a browser. The first form will ask for the values of the fields of the first request, and from there the flow will be handled by the browser. If nobody is listening at the redirection URI the flow will end in a 404 Not Found error, but the code should be visible in the URI of the browser

    http://client.uri?code=MWOqlwshyblAHm3AvNPFf2c96tAtZYsG&state=foo

    http://127.0.0.1:8000/authorization_code?response_type=code&client_id=Client1&redirect_uri=http://client.uri&scope=root1.z+root2.a&state=foo"

### Implicit Grant

Open the following URL in a browser

    (http://127.0.0.1:8000/authorization_token?response_type=token&client_id=AnyClient&redirect_uri=http://anyclient.uri&scope=root1.z+root2.a&state=foo)

Enter ```User1``` in user and ```Password1``` in password. Click Accept. The browser should be redirected to a URL that contains the authorization code in a parameter like

    http://anyclient.uri/?access_token=bHcbA5Q8OHlZyODcR4JwO7JOrD8bto2K&token_type=bearer&expires_in=3600&scope=root1.z root2.b&state=foo

Alternatively, you can use curl to request a token with

    $ curl -v -X POST http://127.0.0.1:8000/authorization_token -d "response_type=token&client_id=AnyClient&redirect_uri=http://anyclient.uri&scope=root1.z+root2.b&state=foo&username=User1&password=Password1"

The server responds with a HTTP 302 status, and the access token is in the Location field of the header

    Location: http://anyclient.uri?access_token=bHcbA5Q8OHlZyODcR4JwO7JOrD8bto2K&token_type=bearer&expires_in=3600&scope=root1.z root2.b&state=foo

### Resource Owner Password Credentials Grant

Send an access token request with

    $ curl -v -X POST http://127.0.0.1:8000/owner_token -d "grant_type=password&username=User1&password=Password1&scope=root1.z+root2.c.d"

### Client Credentials Grant

Send an access token request with

    $ curl -v -X POST http://127.0.0.1:8000/client_token -d "grant_type=client_credentials&client_id=Client1&client_secret=Secret1&scope=root.a.c"

### Refreshing an Access Token

If the Authorization Code Grant flow is performed succesfully, the response to the final request should include a refresh token as follows

    "refresh_token":"EydKXViAHx7aAedoiGsKrrlBQneMpjpf"

Obtain a new access token from the refresh token with 

    $ curl -v -X POST http://127.0.0.1:8000/refresh_token -d "grant_type=refresh_token&client_id=Client1&client_secret=Secret1&refresh_token=EydKXViAHx7aAedoiGsKrrlBQneMpjpf&scope=root1.z+root2.a"

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
4.1.1 Authorization Request

The redirect_uri parameter is required.

4.1.2.1. Error Response

The following errors may occur before the redirection URI is verified, so they are not forwarded to any URI. They are the direct response to the request.

- HTTP 400 Bad Request: The request is missing some of the following parameters: response_type (or its value isn't "code"), client_id or redirection_uri. If it is a POST request, this error is also returned when username or password are missing. 
- HTTP 403 Forbidden: The value of cliend_id or redirection_uri doesn't match a registered client.

Any other error or successful response is forwarded to the registered redirection URI of the client with a HTTP 302 response, as explained in the specification.

*Notice response_type errors are not forwarded to the redirection URI as required by the specification.*

4.1.3. Access Token Request

The redirect_uri parameter is required.

5.2. Error Response

- invalid_request: If the request has a repeated parameter, the value of the first occurrence will be taken without necessarily producing an error.

- invalid_client: This error is returned in a HTTP 401 Unauthoized response.

- unsupported_grant_type: Since this implementation uses a different URL path for each grant type, issuing a wrong grant_type value for a certain path (i.e. http:/localhost:8000/client_token?grant_type=password) results in a unsupported_grant_type error. In cases like this the error doesn't mean that the grant type isn't supported at all, only that it's being sent to the wrong URL.

## Feedback

Please open a Github issue or Pull Request if you:

- Find any security issue, besides the intended use of clear-text HTTP.
- Find any disagreement with the mentioned OAuth 2 specification.
- Have any comment or suggestion.

Your feedback is greatly appreciated.
