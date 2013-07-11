%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.1 Implicit Grant, step 2 of 2.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(authorization_token_form).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").
-include("../include/oauth2_request.hrl").

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
                                                           Scope) of
                                {ok, Authorization} ->
                                    Response = oauth2:issue_token(
                                                 Authorization),
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
