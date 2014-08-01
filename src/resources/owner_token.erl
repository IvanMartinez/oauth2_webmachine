%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.3 Resource Owner Password Credentials Grant.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(owner_token).
-export([init/1, 
         allowed_methods/2,
         malformed_request/2,
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(request, {username          :: binary(),
                  password          :: binary(),
                  scope = undefined :: oauth2:scope() | undefined
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
    OwnerCredentials = oauth2_wrq:get_owner_credentials(Params), 
    if
        GrantType /= password ->
            {true, ReqData, Context};
        OwnerCredentials == undefined ->
            {true, ReqData, Context};
        true ->
            Scope = oauth2_wrq:get_scope(Params),
            {Username, Password} = OwnerCredentials,
            {false, ReqData, [{request, #request{username = Username,
                                                 password = Password,
                                                 scope = Scope}} |
                                Context]}
    end.

process_post(ReqData, Context) ->
    #request{username = Username,
             password = Password,
             scope = Scope} = proplists:get_value(request, Context),
    case oauth2:authorize_password(Username, Password, Scope, none) of
        {ok, {_AppContext, Authorization}} ->
            {ok, {_AppContext, Response}} = 
                oauth2:issue_token(Authorization, none),
            {ok, AccessToken} = oauth2_response:access_token(Response),
            {ok, Type} = oauth2_response:token_type(Response),
            {ok, Expires} = oauth2_response:expires_in(Response),
            {ok, VerifiedScope} = oauth2_response:scope(Response),
            oauth2_wrq:access_token_response(ReqData, AccessToken, Type,
                                             Expires, VerifiedScope, Context);
        {error, Error} ->
            oauth2_wrq:json_error_response(ReqData, Error, Context)
    end.
