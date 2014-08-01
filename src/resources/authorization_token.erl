%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Implements RFC6749 4.2 Implicit Grant
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(authorization_token).
-export([init/1,
         allowed_methods/2, 
         malformed_request/2, 
         to_html/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(request, {client_id             :: binary(),
                  redirect_uri          :: binary(),
                  scope                 :: binary() | oauth2:scope() |
                                           undefined,
                  state                 :: binary() | undefined,
                  username = undefined  :: binary() | undefined,
                  password = undefined  :: binary() | undefined
                 }).

%% ====================================================================
%% API functions
%% ====================================================================

init([]) -> {ok, undefined}.

allowed_methods(ReqData, Context) ->
    {['GET', 'POST', 'HEAD'], ReqData, Context}.

malformed_request(ReqData, Context) ->
    WrqMethod = wrq:method(ReqData),
    case WrqMethod of
        'GET' ->
            Params = wrq:req_qs(ReqData);
        'POST' ->
            Params = oauth2_wrq:parse_body(ReqData)
    end,
    ResponseType = oauth2_wrq:get_response_type(Params),
    ClientId = oauth2_wrq:get_client_id(Params),
    Uri = oauth2_wrq:get_redirect_uri(Params),
    State = oauth2_wrq:get_state(Params),
    OwnerCredentials = oauth2_wrq:get_owner_credentials(Params), 
    if
        ResponseType /= token ->
            %% @todo 4.2.2.1 of the spec requires an unsupported_response_type
            %% error to be send to the redirection URI in this case, but that
            %% is messy to implement with the current API of kivra/ouauth2.
            {true, ReqData, Context};
        ClientId == undefined ->
            {true, ReqData, Context};
        Uri == undefined ->
            %% @todo 4.2.1 of the spec says the redirection URI is optional, 
            %% but it's not clear about what to do when it is missing.
            {true, ReqData, Context};
        (WrqMethod == 'POST') and (OwnerCredentials == undefined) ->
            {true, ReqData, Context};
        (WrqMethod == 'GET') ->
            Scope = oauth2_wrq:get_scope_binary(Params),
            {false, ReqData, [{request, #request{client_id = ClientId,
                                                 redirect_uri = Uri,
                                                 scope = Scope,
                                                 state = State}} |
                                Context]};
        true ->
            Scope = oauth2_wrq:get_scope(Params),
            {Username, Password} = OwnerCredentials,
            {false, ReqData, [{request, #request{client_id = ClientId,
                                                 redirect_uri = Uri,
                                                 scope = Scope,
                                                 state = State,
                                                 username = Username,
                                                 password = Password}} |
                                Context]}
    end.

-spec to_html(ReqData   :: #wm_reqdata{},
              Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
to_html(ReqData, Context) ->
    #request{client_id = ClientId,
             redirect_uri = RedirectURI,
             scope = Scope,
             state = State} = proplists:get_value(request, Context),
    oauth2_wrq:html_response(
      ReqData, 
      200,
      << <<"<html><body>Application ">>/binary, ClientId/binary,
         <<" wants to access scope ">>/binary, Scope/binary,
         <<"<br><form action=\"authorization_token\" method=\"post\">"
           "User: <input type=\"text\" name=\"username\"><br>"
           "Password: <input type=\"password\" name=\"password\"><br>"
           "<input type=\"hidden\" name=\"response_type\" value=\"token\"><br>"
           "<input type=\"hidden\" name=\"client_id\" value=\"">>/binary,
           ClientId/binary, <<"\"><br>"
           "<input type=\"hidden\" name=\"redirect_uri\" value=\"">>/binary,
           RedirectURI/binary, <<"\"><br>"
           "<input type=\"hidden\" name=\"scope\" value=\"">>/binary,
           Scope/binary, <<"\"><br>"
           "<input type=\"hidden\" name=\"state\" value=\"">>/binary,
           State/binary, <<"\"><br>"
           "<input type=\"submit\" value=\"Accept\">"
           "</form></body></html>">>/binary >>,
      Context).

-spec process_post(ReqData   :: #wm_reqdata{},
                   Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
process_post(ReqData, Context) ->
    #request{redirect_uri = RedirectURI,
             scope = Scope,
             state = State,
             username = Username,
             password = Password} = proplists:get_value(request, Context),
    case oauth2:authorize_password(Username, Password, Scope, none) of
        {ok, {_AppContext, Authorization}} ->
            {ok, {_AppContext, Response}} = 
                oauth2:issue_token(Authorization, none),
            {ok, AccessToken} = oauth2_response:access_token(Response),
            {ok, Type} = oauth2_response:token_type(Response),
            {ok, Expires} = oauth2_response:expires_in(Response),
            {ok, VerifiedScope} = oauth2_response:scope(Response),
            oauth2_wrq:redirected_access_token_response(ReqData, 
                                                        RedirectURI, 
                                                        AccessToken,
                                                        Type, 
                                                        Expires, 
                                                        VerifiedScope,
                                                        State, 
                                                        Context);
        {error, Error} ->
            oauth2_wrq:redirected_error_response(
                ReqData, RedirectURI, Error, State, Context)
    end.
