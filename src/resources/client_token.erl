%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.4 Client Credentials Grant.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(client_token).
-export([init/1, 
         allowed_methods/2,
         malformed_request/2,
         is_authorized/2,
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(request, {scope                     :: oauth2:scope() |
                                               undefined,
                  client_id = undefined     :: binary() | undefined,
                  client_secret = undefined :: binary() | undefined 
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
    if
        GrantType /= client_credentials ->
            {true, ReqData, Context};
        true ->
            Scope = oauth2_wrq:get_scope(Params),
            {false, ReqData, [{request, #request{scope = Scope}} |
                                  Context]}
    end.

is_authorized(ReqData, Context) ->
    Params = oauth2_wrq:parse_body(ReqData),
    case oauth2_wrq:get_client_credentials(Params, ReqData) of
        undefined ->
            {"Basic", ReqData, Context};
        {ClientId, ClientSecret} ->
            Request = proplists:get_value(request, Context),
            {true, ReqData, [{authorized_request, 
                              Request#request{client_id = ClientId,
                                              client_secret = ClientSecret}} |
                                Context]}
    end.

process_post(ReqData, Context) ->
    #request{scope = Scope,
             client_id = ClientId,
             client_secret = ClientSecret} = 
                proplists:get_value(authorized_request, Context),
    case oauth2:authorize_client_credentials(ClientId, ClientSecret, Scope,
                                             none) of
        {ok, {_AppContext, Authorization}} ->
            {ok, {_AppContext, Response}} = 
                oauth2:issue_token(Authorization, none),
            {ok, Token} = 
                oauth2_response:access_token(Response),
            {ok, Type} = oauth2_response:token_type(Response),
            {ok, Expires} = 
                oauth2_response:expires_in(Response),
            {ok, Scope} = oauth2_response:scope(Response),
            oauth2_wrq:access_token_response(ReqData, Token,
                                             Type, Expires,
                                             Scope, Context);
        {error, invalid_scope} ->
            oauth2_wrq:json_error_response(ReqData,
                                           invalid_scope, 
                                           Context);
        {error, invalid_client} ->
            oauth2_wrq:json_error_response(ReqData, 
                                           invalid_client,
                                           Context)
    end.
