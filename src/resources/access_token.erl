%% @author https://github.com/IvanMartinez
%% @copyright 2013-2014 author.
%% @doc Implements RFC6749 4.1 Authorization Code Grant, Access Token.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(access_token).

-export([init/1, 
         allowed_methods/2,
         malformed_request/2,
         is_authorized/2,
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(request, {grant_type                :: atom(),
                  code                      :: oauth2:token(),
                  redirect_uri              :: binary(),
                  client_credentials = {undefined, undefined}
                                :: {binary() | undefined, 
                                    binary() | undefined}
                 }).

%% ====================================================================
%% API functions
%% ====================================================================

init([]) -> {ok, undefined}.

allowed_methods(ReqData, Context) ->
    {['POST', 'HEAD'], ReqData, Context}.

malformed_request(ReqData, Context) ->
    Params = oauth2_wrq:parse_body(ReqData),
    GrantType = oauth2_wrq:get_grant_type(Params),
    Code = oauth2_wrq:get_code(Params),
    RedirectUri = oauth2_wrq:get_redirect_uri(Params),
    if
        GrantType == undefined ->
            {true, ReqData, Context};
        Code == undefined ->
            {true, ReqData, Context};
        RedirectUri == undefined ->
            {true, ReqData, Context};
        true ->
            {false, ReqData, [{request, 
                               #request{grant_type = GrantType,
                                        code = Code,
                                        redirect_uri = RedirectUri}} |
                                Context]}
    end.

is_authorized(ReqData, Context) ->
    Params = oauth2_wrq:parse_body(ReqData),
    case oauth2_wrq:get_client_credentials(Params, ReqData) of
        undefined ->
            {"Basic", ReqData, Context};
        ClientCredentials ->
            Request = proplists:get_value(request, Context),
            {true, ReqData, [{authorized_request, 
                              Request#request{client_credentials = 
                                                  ClientCredentials}} |
                                 Context]}
    end.
    
process_post(ReqData, Context) ->
    #request{grant_type = GrantType,
             code = Code,
             redirect_uri = RedirectURI,
             client_credentials = ClientCredentials} = 
                proplists:get_value(authorized_request, Context),
    case GrantType of
        authorization_code ->
            case oauth2:authorize_code_grant(ClientCredentials, Code, 
                                             RedirectURI, none) of
                {ok, {_AppContext, Authorization}} ->
                    {ok, {_AppContext, Response}} = 
                        oauth2:issue_token_and_refresh(Authorization, none),
                    {ok, AccessToken} = oauth2_response:access_token(Response),
                    {ok, Type} = oauth2_response:token_type(Response),
                    {ok, Expires} = oauth2_response:expires_in(Response),
                    {ok, RefreshToken} = oauth2_response:refresh_token(
                                           Response),
                    {ok, Scope} = oauth2_response:scope(Response),
                    oauth2_wrq:access_refresh_token_response(ReqData, 
                                                             AccessToken, 
                                                             Type,
                                                             Expires, 
                                                             RefreshToken, 
                                                             Scope, 
                                                             Context);
                {error, Error} ->
                    oauth2_wrq:json_error_response(ReqData, Error, Context)
            end;
        _ ->
            oauth2_wrq:json_error_response(ReqData, unsupported_grant_type,
                                           Context)
    end.
