%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Example webmachine_resource.

-module(authorization_code).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) ->
    {['GET', 'POST'], ReqData, State}.

content_types_provided(ReqData, State) ->
    {[{"text/html", process_get}], ReqData, State}.

process_get(ReqData, State) ->
    {HttpStatus, Body} = process(wrq:req_qs(ReqData)),
    {{halt, HttpStatus}, wrq:set_resp_body(Body, ReqData), State}.

process_post(ReqData, State) ->
    error_logger:info_msg("process_post~n", []),
    {HttpStatus, Body} = process(oauth2_wrq:parse_body(ReqData)),
    {{halt, HttpStatus}, wrq:set_resp_body(Body, ReqData), State}.

-spec process(Params :: list(string())) ->
    {non_neg_integer(), binary()}.
process(Params) ->
    error_logger:info_msg("Params ~p~n", [Params]),
    case oauth2_wrq:get_response_type(Params) of
        code ->
            case oauth2_wrq:get_client_id(Params) of
                undefined ->
                    {400, html:bad_request()};
                ClientId ->
                    RedirectUri = oauth2_wrq:get_redirect_uri(Params),
                    Scope = oauth2_wrq:get_scope(Params),        
                    ScopeString = case lists:keyfind("scope", 1, Params) of
                        {"scope", ""} ->
                            "none";
                        {"scope", AScope} ->
                            AScope;
                        false ->
                            "default"
                    end,
                    StateParam = oauth2_wrq:get_state(Params),
                    RequestId = oauth2_ets_backend:store_request(ClientId, RedirectUri, Scope, StateParam),
                    {200, html:authorization_form(ClientId, ScopeString, RequestId)}
            end;
        undefined ->
            {400, html:bad_request()};
        _ ->
            {400, html:unsupported_response_type()}
    end.
