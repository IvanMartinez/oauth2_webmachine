%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.3 Resource Owner Password Credentials Grant.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(owner_token).
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
    {[{"application/json;charset=UTF-8", process_get}], ReqData, Context}.

process_get(ReqData, Context) ->
    process(ReqData, wrq:req_qs(ReqData), Context).

process_post(ReqData, Context) ->
    process(ReqData, oauth2_wrq:parse_body(ReqData), Context).

%% ====================================================================
%% Internal functions
%% ====================================================================

process(ReqData, Params, Context) ->
    case oauth2_wrq:get_grant_type(Params) of
        password ->
            case oauth2_wrq:get_owner_credentials(Params) of
                undefined ->
                    oauth2_wrq:json_error_response(ReqData, invalid_request,
                                                   Context);
                {Username, Password} ->
                    case oauth2:authorize_password(Username, Password, 
                                                   oauth2_wrq:get_scope(Params))
                        of
                        {ok, Authorization} ->
                            Response = oauth2:issue_token_and_refresh(
                                         Authorization),
                            {ok, Token} = 
                                oauth2_response:access_token(Response),
                            {ok, Type} = oauth2_response:token_type(Response),
                            {ok, Expires} = 
                                oauth2_response:expires_in(Response),
                            {ok, Scope} = oauth2_response:scope(Response),
                            oauth2_wrq:access_token_response(ReqData, 
                                                          binary_to_list(Token),
                                                          binary_to_list(Type),
                                                          Expires, Scope,
                                                          Context);
                        {error, invalid_scope} ->
                            oauth2_wrq:json_error_response(ReqData, 
                                                           invalid_scope, 
                                                           Context);
                        {error, _Reason} ->
                            oauth2_wrq:json_error_response(ReqData, 
                                                           invalid_grant, 
                                                           Context)
                    end
            end;
        undefined ->
            oauth2_wrq:json_error_response(ReqData, invalid_request, Context);
        _ ->
            oauth2_wrq:json_error_response(ReqData, unsupported_grant_type,
                                           Context)
    end.
