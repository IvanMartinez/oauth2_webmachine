%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 6 Refreshing an Access Token.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(refresh_token).

-export([init/1, 
         allowed_methods/2,
         malformed_request/2,
         is_authorized/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(request, {refresh_token             :: oauth2:token(),
                  scope = undefined         :: oauth2:scope() | undefined,
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
    RefreshToken = oauth2_wrq:get_refresh_token(Params),
    if
        GrantType /= refresh_token ->
            {true, ReqData, Context};
        RefreshToken == undefined ->
            {true, ReqData, Context};
        true ->
            Scope = oauth2_wrq:get_scope(Params),
            {false, ReqData, [{request, 
                               #request{refresh_token = RefreshToken,
                                        scope = Scope}} |
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
    #request{refresh_token = RefreshToken,
             scope = Scope,
             client_id = ClientId,
             client_secret = ClientSecret} =
                proplists:get_value(authorized_request, Context),
    case oauth2:refresh_access_token(ClientId, ClientSecret, RefreshToken, 
                                     Scope, none) of
        {ok, {_AppContext, Response}} ->
            {ok, AccessToken} = 
                oauth2_response:access_token(Response),
            {ok, Type} = 
                oauth2_response:token_type(Response),
            {ok, Expires} = 
                oauth2_response:expires_in(Response),
            {ok, ResponseScope} = 
                oauth2_response:scope(Response),
            oauth2_wrq:access_token_response(
              ReqData, AccessToken, Type, Expires,
              ResponseScope, Context);
        {error, invalid_client} ->
            oauth2_wrq:json_error_response(
              ReqData, invalid_client, Context);
        {error, invalid_grant} ->
            oauth2_wrq:json_error_response(
              ReqData, invalid_grant, Context);
        {error, invalid_scope} ->
            oauth2_wrq:json_error_response(
              ReqData, invalid_scope, Context)
    end.
