%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.2 Implicit Grant, step 1 of 2.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(authorization_token).
-export([init/1, allowed_methods/2, to_html/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").
-include("../include/oauth2_request.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, Context) ->
    {['GET', 'POST'], ReqData, Context}.

-spec to_html(ReqData   :: #wm_reqdata{},
              Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
to_html(ReqData, Context) ->
    Params = wrq:req_qs(ReqData),
    case oauth2_wrq:get_client_id(Params) of
        undefined ->
            oauth2_wrq:html_response(ReqData, 400, html:bad_request(), Context);
        ClientId ->
            case oauth2_wrq:get_redirect_uri(Params) of
                undefined ->
                    %% no uri
                    oauth2_wrq:html_response(ReqData, 401,
                                             html:invalid_redirection_uri(),
                                             Context);
                RedirectUri ->
                    StateParam = oauth2_wrq:get_state(Params),
                    case oauth2_wrq:get_response_type(Params) of
                        token ->
                            Scope = oauth2_wrq:get_scope(Params),        
                            RequestId =
                                oauth2_ets_backend:store_request(ClientId, 
                                                                 RedirectUri,
                                                                 Scope,
                                                                 StateParam),
                            ScopeString = scope_string(Params),
                            oauth2_wrq:html_response(ReqData, 200,
                                       html:authorization_form(
                                                    ClientId,
                                                    ScopeString,
                                                    RequestId,
                                                    "authorization_token_form"),
                                       Context);
                        undefined ->
                            oauth2_wrq:redirected_error_response(
                              ReqData, RedirectUri, invalid_request,
                              StateParam, Context);
                        _ ->
                            oauth2_wrq:redirected_error_response(
                              ReqData, RedirectUri, unsupported_response_type,
                              StateParam, Context)
                    end
            end
    end.

-spec process_post(ReqData   :: #wm_reqdata{},
                   Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
process_post(ReqData, Context) ->
    Params = oauth2_wrq:parse_body(ReqData),
    case oauth2_wrq:get_request_id(Params) of
        undefined ->
            oauth2_wrq:html_response(ReqData, 400, html:bad_request(), Context);
        RequestId ->
            case oauth2_ets_backend:retrieve_request(
                   RequestId) of
                {ok, #oauth2_request{%%client_id = ClientId, 
                                     redirect_uri = RedirectUri,
                                     scope = Scope, 
                                     state = State}} ->
                    case oauth2_wrq:get_owner_credentials(Params) of
                        undefined ->
                            oauth2_wrq:html_response(ReqData, 400, 
                                                     html:bad_request(),
                                                     Context);
                        {Username, Password} ->
                            case oauth2:authorize_password(Username,
                                                           Password,
                                                           Scope, none) of
                                {ok, Authorization} ->
                                    Response = oauth2:issue_token(
                                                 Authorization, none),
                                    {ok, Token} = oauth2_response:access_token(
                                                    Response),
                                    {ok, Type} =  oauth2_response:token_type(
                                                    Response),
                                    {ok, Expires} = oauth2_response:expires_in(
                                                      Response),
                                    {ok, VerifiedScope} = oauth2_response:scope(
                                                            Response),
                                    oauth2_wrq:
                                    redirected_access_token_response(
                                      ReqData, RedirectUri, Token, Type, 
                                      Expires, VerifiedScope, State, Context);
                                {error, invalid_scope} ->
                                    oauth2_wrq:redirected_error_response(
                                      ReqData, RedirectUri, invalid_scope,
                                      State, Context);
                                {error, access_denied} ->
                                    oauth2_wrq:redirected_error_response(
                                      ReqData, RedirectUri, access_denied,
                                      State, Context)
                            end
                    end;
                {error, _} ->
                    oauth2_wrq:html_response(ReqData, 408, 
                                             html:request_timeout(), Context)
            end
    end.

%% ====================================================================
%% Internal functions
%% ====================================================================

-spec scope_string(Params :: list(string())) ->
          string().
scope_string(Params) ->
    case lists:keyfind("scope", 1, Params) of
        {"scope", ""} ->
            "none";
        {"scope", AScope} ->
            AScope;
        false ->
            "default"
    end.
