%% @author https://github.com/IvanMartinez
%% @copyright YYYY author.
%% @doc Example webmachine_resource.

-module(html).
-export([authorization_form/4, bad_request/0, invalid_client/0, 
         invalid_redirection_uri/0, unauthorized/0, unauthorized_client/0, 
         request_timeout/0]).

-spec authorization_form(ClientId   :: string() | binary(),
                         Scope      :: string() | binary(),
                         RequestId  :: string() | binary(),
                         Action     :: string() | binary()
                        ) -> binary().
authorization_form(ClientId, Scope, RequestId, Action)->
    list_to_binary(io_lib:format("<html><body>" ++
        "Application ~s wants to access scope ~s<br>" ++
        "<form action=\"~s\" method=\"post\">" ++
        "User: <input type=\"text\" name=\"username\"><br>" ++
        "Password: <input type=\"password\" name=\"password\"><br>" ++
        "<input type=\"hidden\" name=\"request_id\" value=\"~s\"><br>" ++
        "<input type=\"submit\" value=\"Accept\">"
        "</form>"
        "</body></html>", [ClientId, Scope, Action, RequestId])).

-spec bad_request() -> binary().
bad_request() ->
    <<"<html><body>Bad request</body></html>">>.

-spec invalid_client() -> binary().
invalid_client() ->
    <<"<html><body>Invalid client</body></html>">>.

-spec invalid_redirection_uri() -> binary().
invalid_redirection_uri() ->
    <<"<html><body>Invalid redirection URI</body></html>">>.

-spec unauthorized() -> binary().
unauthorized() ->
    <<"<html><body>Unauthorized</body></html>">>.

-spec unauthorized_client() -> binary().
unauthorized_client() ->
    <<"<html><body>Unauthorized client</body></html>">>.

-spec request_timeout() -> binary().
request_timeout() ->
    <<"<html><body>Request timeout</body></html>">>.

  