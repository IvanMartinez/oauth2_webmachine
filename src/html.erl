%% @author https://github.com/IvanMartinez
%% @copyright YYYY author.
%% @doc Example webmachine_resource.

-module(html).
-export([authorization_form/3, bad_request/0, unsupported_response_type/0, invalid_client/0, unauthorized/0,
         request_timeout/0]).

-spec authorization_form(ClientId  :: string() | binary(),
                          Scope     :: string() | binary(),
                          RequestId :: string() | binary()
                         ) -> binary().
authorization_form(ClientId, Scope, RequestId)->
    %io_lib:format("hola", []).
    list_to_binary(io_lib:format("<html><body>" ++
        "Application ~s wants to access scope ~s<br>" ++
        "<form action=\"/authorization_form\" method=\"post\">" ++
        "User: <input type=\"text\" name=\"username\"><br>" ++
        "Password: <input type=\"password\" name=\"password\"><br>" ++
        "<input type=\"hidden\" name=\"request_id\" value=\"~s\"><br>" ++
        "<input type=\"submit\" value=\"Accept\">"
        "</form>"
        "</body></html>", [ClientId, Scope, RequestId])).

-spec bad_request() -> binary().
bad_request() ->
    <<"<html><body>Bad request</body></html>">>.

-spec unsupported_response_type() -> binary().
unsupported_response_type() ->
    <<"<html><body>Unsupported response type</body></html>">>.

-spec invalid_client() -> binary().
invalid_client() ->
    <<"<html><body>Invalid client</body></html>">>.

-spec unauthorized() -> binary().
unauthorized() ->
    <<"<html><body>Unauthorized</body></html>">>.

-spec request_timeout() -> binary().
request_timeout() ->
    <<"<html><body>Request timeout</body></html>">>.

  