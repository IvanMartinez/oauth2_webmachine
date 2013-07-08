%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.2 Implicit Grant, step 1 of 2.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(authorization_token).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, Context) ->
    {['GET', 'POST'], ReqData, Context}.

content_types_provided(ReqData, Context) ->
    {[{"text/html", process_get}], ReqData, Context}.

process_get(ReqData, Context) ->
    process(ReqData, wrq:req_qs(ReqData), Context).

process_post(ReqData, Context) ->
    process(ReqData, oauth2_wrq:parse_body(ReqData), Context).

%% ====================================================================
%% Internal functions
%% ====================================================================

-spec process(ReqData   :: #wm_reqdata{},
              Params    :: list(string()),
              Context   :: term()) ->
          {{halt, pos_integer()}, #wm_reqdata{}, _}.
process(ReqData, Params, Context) ->
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
