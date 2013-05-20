%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Example webmachine_resource.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(authorization_code).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").
-type(wm_reqdata() :: #wm_reqdata{}).

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

-spec process(ReqData   :: wm_reqdata(),
              Params    :: list(string()),
              Context   :: term()) ->
          wm_reqdata().
process(ReqData, Params, Context) ->
    case oauth2_wrq:get_client_id(Params) of
        undefined ->
            oauth2_wrq:html_response(ReqData, 400, html:bad_request(), Context);
        ClientId ->
            case oauth2_ets_backend:get_redirection_uri(ClientId) of
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
                                               html:authorization_form(ClientId,
                                                                    ScopeString,
                                                                    RequestId),
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
