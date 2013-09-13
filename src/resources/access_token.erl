%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.1 Authorization Code Grant, step 3 of 3.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(access_token).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

%% ====================================================================
%% API functions
%% ====================================================================

init([]) -> {ok, undefined}.

allowed_methods(ReqData, Context) ->
    {['GET', 'POST'], ReqData, Context}.

content_types_provided(ReqData, Context) ->
    {[{"application/json;charset=UTF-8", process_get},
      {"application/json;charset=UTF-8", process_post}], ReqData, Context}.

process_get(ReqData, Context) ->
    process(ReqData, wrq:req_qs(ReqData), Context).

process_post(ReqData, Context) ->
    process(ReqData, oauth2_wrq:parse_body(ReqData), Context).

%% ====================================================================
%% Internal functions
%% ====================================================================

process(ReqData, Params, Context) ->
    case oauth2_wrq:get_grant_type(Params) of
        authorization_code ->
            case oauth2_wrq:get_code(Params) of
                undefined ->
                    oauth2_wrq:json_error_response(ReqData, invalid_request, 
                                                   Context);
                Code ->
                    case oauth2_wrq:get_redirect_uri(Params) of
                        undefined ->
                            oauth2_wrq:json_error_response(ReqData,
                                                           invalid_request, 
                                                           Context);
                        RedirectUri ->
                            case oauth2_wrq:get_client_credentials(Params,
                                                                   ReqData) of
                                undefined ->
                                    oauth2_wrq:json_error_response(
                                      ReqData, invalid_client, Context);
                                {ClientId, ClientSecret} ->
                                    case oauth2:authorize_code_grant(
                                           ClientId, ClientSecret, Code, 
                                           RedirectUri, none) of
                                        {ok, Authorization} ->
                                            Response = 
                                                oauth2:issue_token_and_refresh(
                                                  Authorization, none),
                                            {ok, AccessToken} = 
                                                oauth2_response:access_token(
                                                  Response),
                                            {ok, Type} = 
                                                oauth2_response:token_type(
                                                  Response),
                                            {ok, Expires} = 
                                                oauth2_response:expires_in(
                                                  Response),
                                            {ok, RefreshToken} = 
                                                oauth2_response:refresh_token(
                                                  Response),
                                            {ok, Scope} = 
                                                oauth2_response:scope(Response),
                                            oauth2_wrq:
                                            access_refresh_token_response(
                                              ReqData, AccessToken, Type,
                                              Expires, RefreshToken, Scope,
                                              Context);
                                        {error, invalid_client} ->
                                            oauth2_wrq:json_error_response(
                                              ReqData, invalid_client, Context);
                                        {error, invalid_grant} ->
                                            oauth2_wrq:json_error_response(
                                              ReqData, invalid_grant, Context)
                                    end
                            end
                    end
            end;
        undefined ->
            oauth2_wrq:json_error_response(ReqData, invalid_request, Context);
        _ ->
            oauth2_wrq:json_error_response(ReqData, unsupported_grant_type,
                                           Context)
    end.
