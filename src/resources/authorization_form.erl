%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Example webmachine_resource.

-module(authorization_form).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").
-include("../include/oauth2_request.hrl").

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

-spec process(ReqData   :: wm_reqdata(),
              Params    :: list(string()),
              Context   :: term()) ->
          wm_reqdata().
process(ReqData, Params, Context) ->
error_logger:info_msg("authorization_form Params ~p~n", [Params]),
    case oauth2_wrq:get_request_id(Params) of
        undefined ->
            oauth2_wrq:html_response(ReqData, 400, html:bad_request(), Context);
        RequestId ->
            case oauth2_wrq:get_owner_credentials(Params) of
                undefined ->
                    oauth2_wrq:html_response(ReqData, 400, html:bad_request(), Context);
                {Username, Password} ->
error_logger:info_msg("username ~p~n", [Username]),
error_logger:info_msg("password ~p~n", [Password]),
                    case oauth2_ets_backend:authenticate_username_password(
                           Username, Password) of
                        {ok, OwnerIdentity} ->
                            case oauth2_ets_backend:retrieve_request(
                                   RequestId) of
                                {ok, #oauth2_request{client_id = ClientId, 
                                                     redirect_uri = RedirectUri,
                                                     scope = Scope, 
                                                     state = State}} ->
error_logger:info_msg("ClientId ~p~n", [ClientId]),
error_logger:info_msg("RedirectUri ~p~n", [RedirectUri]),
error_logger:info_msg("Scope ~p~n", [Scope]),
error_logger:info_msg("State ~p~n", [State]),
                                    issue_code_grant(ClientId, RedirectUri, 
                                                     OwnerIdentity, Scope, 
                                                     State);
                                {error, _} ->
                                    {408, html:request_timeout(), <<>>}
                            end;
                        {error, _} ->
                            {401, html:unauthorized(), <<>>}
                    end
                    
            end
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec issue_code_grant(ClientId, RedirectionUri, OwnerIdentity, Scope, State)
                       -> {ok, Identity, Response} | {error, Reason} when
      ClientId          :: binary(),
      RedirectionUri    :: binary() | undefined,
      OwnerIdentity     :: term(),
      Scope             :: binary(),
      State             :: binary() | undefined,
      Identity          :: term(),
      Response          :: oauth2_response:response(),
      Reason            :: binary().
issue_code_grant(ClientId, RedirectionUri, OwnerIdentity, Scope, State) ->
    ok.
            

