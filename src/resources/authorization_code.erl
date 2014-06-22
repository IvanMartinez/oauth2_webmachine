%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.1 Authorization Code Grant, step 1 of 3.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(authorization_code).
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
            case oauth2_ets_backend:get_redirection_uri(ClientId, none) of
                {ok, RegisteredUri} ->
                    case verify_redirection_uri(
                           oauth2_wrq:get_redirect_uri(Params),
                           RegisteredUri) of
                        {match, _} ->
                            StateParam = oauth2_wrq:get_state(Params),
                            case oauth2_wrq:get_response_type(Params) of
                                code ->
                                    Scope = oauth2_wrq:get_scope(Params),        
                                    RequestId =
                                        oauth2_ets_backend:store_request(
                                          ClientId, RegisteredUri, Scope,
                                          StateParam),
                                    ScopeString = scope_string(Params),
                                    oauth2_wrq:html_response(ReqData, 200,
                                               html:authorization_form(
                                                     ClientId,
                                                     ScopeString,
                                                     RequestId,
                                                     "authorization_code_form"),
                                               Context);
                                undefined ->
                                    oauth2_wrq:redirected_error_response(
                                      ReqData, RegisteredUri, invalid_request,
                                      StateParam, Context);
                                _ ->
                                    oauth2_wrq:redirected_error_response(
                                      ReqData, RegisteredUri,
                                      unsupported_response_type, StateParam, 
                                      Context)
                            end;
                        {mismatch, none_registered} ->
                            oauth2_wrq:html_response(ReqData, 403,
                                                     html:unauthorized_client(),
                                                     Context);
                        {mismatch, different} ->
                            oauth2_wrq:html_response(ReqData, 401,
                                                 html:invalid_redirection_uri(),
                                                 Context)
                    end;
                _ ->
                    oauth2_wrq:html_response(ReqData, 401, html:unauthorized(),
                                             Context)
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
                {ok, #oauth2_request{client_id = ClientId, 
                                     redirect_uri = RedirectUri,
                                     scope = Scope, 
                                     state = State}} ->
                    case oauth2_wrq:get_owner_credentials(Params) of
                        undefined ->
                            oauth2_wrq:html_response(ReqData, 400, 
                                                     html:bad_request(),
                                                     Context);
                        {Username, Password} ->
                            case oauth2:authorize_code_request(ClientId,
                                                               RedirectUri,
                                                               Username,
                                                               Password,
                                                               Scope, none) of
                                {ok, Authorization} ->
                                    Response = oauth2:issue_code(
                                                 Authorization, none),
                                    {ok, Code} =
                                        oauth2_response:access_code(Response),
                                    oauth2_wrq:
                                    redirected_authorization_code_response(
                                      ReqData, RedirectUri, Code, State, 
                                      Context);
                                {error, unauthorized_client} ->
                                    oauth2_wrq:redirected_error_response(
                                      ReqData, RedirectUri, unauthorized_client,
                                      State, Context);
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

-spec verify_redirection_uri(ParameterUri   :: binary(),
                             RegisteredUri  :: binary()) ->
          {match, atom()} | {mismatch, atom()}.
verify_redirection_uri(ParameterUri, RegisteredUri) ->
    case RegisteredUri of
        <<>> ->
            {mismatch, none_registered};
        _ ->
            case ParameterUri of
                undefined ->
                    {match, no_parameter};
                RegisteredUri ->
                    {match, equal};
                _ ->
                    {mismatch, different}
            end
    end.

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
