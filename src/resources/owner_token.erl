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

-record(request, {grant_type        :: atom(),
                  owner_credentials :: {binary(), binary()},
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
        GrantType == undefined ->
            {true, ReqData, Context};
        OwnerCredentials == undefined ->
            {true, ReqData, Context};
        true ->
            Scope = oauth2_wrq:get_scope(Params),
            {false, ReqData, [{request, #request{grant_type = GrantType,
                                                 owner_credentials =
                                                     OwnerCredentials,
                                                 scope = Scope}} |
                                Context]}
    end.

process_post(ReqData, Context) ->
    #request{grant_type = GrantType,
             owner_credentials = OwnerCredentials,
             scope = Scope} = proplists:get_value(request, Context),
    case GrantType of
        password ->
            case oauth2:authorize_password(OwnerCredentials, Scope, none) of
                {ok, {_AppContext, Authorization}} ->
                    {ok, {_AppContext, Response}} = 
                        oauth2:issue_token(Authorization, none),
                    {ok, AccessToken} = oauth2_response:access_token(Response),
                    {ok, Type} = oauth2_response:token_type(Response),
                    {ok, Expires} = oauth2_response:expires_in(Response),
                    {ok, VerifiedScope} = oauth2_response:scope(Response),
                    oauth2_wrq:access_token_response(ReqData, AccessToken, Type,
                                                     Expires, VerifiedScope, 
                                                     Context);
                {error, Error} ->
                    oauth2_wrq:json_error_response(ReqData, Error, Context)
            end;
        _ ->
            oauth2_wrq:json_error_response(ReqData, unsupported_grant_type,
                                           Context)
    end.
            

