%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc OAuth2 backend functions.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(oauth2_ets_backend).

-behaviour(oauth2_backend).


-include("include/oauth2_request.hrl").

%%% API
-export([start/0, stop/0, add_resowner/2, add_resowner/3, delete_resowner/1, 
         add_client/4, delete_client/1, store_request/4, retrieve_request/1, 
         get_user_identity/1 
        ]).

%%% OAuth2 backend functionality
-export([authenticate_username_password/2, authenticate_client/2, 
         associate_access_code/2, associate_access_token/2,
         associate_refresh_token/2, resolve_access_code/1, 
         resolve_access_token/1, resolve_refresh_token/1, 
         revoke_access_code/1, revoke_access_token/1, revoke_refresh_token/1, 
         get_client_identity/1, get_redirection_uri/1, 
         verify_redirection_uri/2, verify_client_scope/2,
         verify_resowner_scope/2
        ]).

-define(ACCESS_CODE_TABLE, access_codes).
-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).
-define(USER_TABLE, users).
-define(CLIENT_TABLE, clients).
-define(REQUEST_TABLE, requests).

-define(TABLES, [?ACCESS_CODE_TABLE,
                 ?ACCESS_TOKEN_TABLE,
                 ?REFRESH_TOKEN_TABLE,
                 ?USER_TABLE,
                 ?CLIENT_TABLE,
                 ?REQUEST_TABLE]).

-record(client, {
          client_id     :: binary(),
          client_secret :: binary(),
          redirect_uri  :: binary(),
          scope         :: [binary()]
         }).

-record(resowner, {
          username  :: binary(),
          password  :: binary(),
          scope     :: [binary()]
         }).

%%%===================================================================
%%% API
%%%===================================================================

-spec start() -> ok.
start() ->
    lists:foreach(fun(Table) ->
                          ets:new(Table, [named_table, public])
                  end,
                  ?TABLES),
    ok.

-spec stop() -> ok.
stop() ->
    lists:foreach(fun ets:delete/1, ?TABLES),
    ok.

-spec add_resowner(Username, Password, Scope) -> ok when
    Username  :: binary(),
    Password  :: binary(),
    Scope     :: [binary()].
add_resowner(Username, Password, Scope) ->
    put(?USER_TABLE, Username, #resowner{username = Username, 
                                         password = Password, scope = Scope}),
    ok.

-spec add_resowner(Username, Password) -> ok when
    Username :: binary(),
    Password :: binary().
add_resowner(Username, Password) ->
    add_resowner(Username, Password, []),
    ok.

-spec delete_resowner(Username) -> ok when
    Username :: binary().
delete_resowner(Username) ->
    delete(?USER_TABLE, Username),
    ok.

-spec add_client(Id, Secret, RedirectURI, Scope) -> ok when
    Id          :: binary(),
    Secret      :: binary(),
    RedirectURI :: binary(),
    Scope       :: [binary()].
add_client(Id, Secret, RedirectURI, Scope) ->
    put(?CLIENT_TABLE, Id, #client{client_id = Id,
                                   client_secret = Secret,
                                   redirect_uri = RedirectURI,
                                   scope = Scope
                                  }),
    ok.

-spec delete_client(Id) -> ok when
    Id :: binary().
delete_client(Id) ->
    delete(?CLIENT_TABLE, Id),
    ok.

-spec store_request(ClientId, RedirectURI, Scope, State) -> oauth2:token() when
    ClientId    :: binary(),
    RedirectURI :: binary(),
    Scope       :: [binary()] | undefined,
    State       :: binary() | undefined.
store_request(ClientId, RedirectURI, Scope, State) ->
    RequestId = new_request_id(),
    put(?REQUEST_TABLE, RequestId, #oauth2_request{client_id = ClientId, 
                                                   redirect_uri = RedirectURI,
                                                   scope = Scope,
                                                   state = State}),
    RequestId.

-spec retrieve_request(RequestId) -> {ok, Request} | {error, notfound} when
    RequestId   :: oauth2:token(),
    Request     :: oauth2_request().
retrieve_request(RequestId) ->
    case get(?REQUEST_TABLE, RequestId) of
        {ok, Request} ->
            {ok, Request};
        {error, notfound} ->
            {error, notfound}
    end.

%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

authenticate_username_password(Username, Password) ->
    case get(?USER_TABLE, Username) of
        {ok, #resowner{password = Password} = Identity} ->
            {ok, Identity};
        {ok, #resowner{password = _WrongPassword}} ->
            {error, badpass};
        _ ->
            {error, notfound}
    end.

authenticate_client(ClientId, ClientSecret) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, #client{client_secret = ClientSecret} = Identity} ->
            {ok, Identity};
        {ok, #client{client_secret = _WrongSecret}} ->
            {error, badsecret};
        _ ->
            {error, notfound}
    end.

associate_access_code(AccessCode, Context) ->
    put(?ACCESS_CODE_TABLE, AccessCode, Context),
    ok.

associate_access_token(AccessToken, Context) ->
    put(?ACCESS_TOKEN_TABLE, AccessToken, Context),
    ok.

associate_refresh_token(RefreshToken, Context) ->
    put(?REFRESH_TOKEN_TABLE, RefreshToken, Context),
    ok.

resolve_access_code(AccessCode) ->
    %% The case trickery is just here to make sure that
    %% we don't propagate errors that cannot be legally
    %% returned from this function according to the spec.
    case get(?ACCESS_CODE_TABLE, AccessCode) of
        Value = {ok, _} ->
            Value;
        Error = {error, notfound} ->
            Error
    end.

resolve_access_token(AccessToken) ->
    %% The case trickery is just here to make sure that
    %% we don't propagate errors that cannot be legally
    %% returned from this function according to the spec.
    case get(?ACCESS_TOKEN_TABLE, AccessToken) of
        Value = {ok, _} ->
            Value;
        Error = {error, notfound} ->
            Error
    end.

%% Not implemented yet.
resolve_refresh_token(_RefreshToken) ->
    {error, not_found}.

%% @doc Revokes an access code AccessCode, so that it cannot be used again.
revoke_access_code(AccessCode) ->
    delete(?ACCESS_CODE_TABLE, AccessCode),
    ok.

%% Not implemented yet.
revoke_access_token(_AccessToken) ->
    {error, not_found}.

%% Not implemented yet.
revoke_refresh_token(_RefreshToken) ->
    {error, not_found}.

get_redirection_uri(ClientId) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, #client{redirect_uri = RedirectUri}} ->
            {ok, RedirectUri};
        Error = {error, notfound} ->
            Error
    end.

get_client_identity(ClientId) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, Identity} ->
            {ok, Identity};
        Error = {error, notfound} ->
            Error
    end.

get_user_identity(Username) ->
    case get(?USER_TABLE, Username) of
        {ok, Identity} ->
            {ok, Identity};
        Error = {error, notfound} ->
            Error
    end.

verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, undefined) ->
    ok;
verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, <<>>) ->
    ok;
verify_redirection_uri(#client{redirect_uri = <<>>}, _Uri) ->
    {error, baduri};
verify_redirection_uri(#client{redirect_uri = RegisteredUri}, RegisteredUri) ->
    ok;
verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, _DifferentUri) ->
    {error, baduri}.

verify_client_scope(#client{scope = RegisteredScope}, undefined) ->
    {ok, RegisteredScope};
verify_client_scope(#client{scope = _RegisteredScope}, []) ->
    {ok, []};
verify_client_scope(#client{scope = []}, _Scope) ->
    {error, invalid_scope};
verify_client_scope(#client{scope = RegisteredScope}, Scope) ->
    case oauth2_priv_set:is_subset(oauth2_priv_set:new(Scope), 
                                   oauth2_priv_set:new(RegisteredScope)) of
        true ->
            {ok, Scope};
        false ->
            {error, badscope}
    end.

verify_resowner_scope(#resowner{scope = RegisteredScope}, undefined) ->
    {ok, RegisteredScope};
verify_resowner_scope(#resowner{scope = _RegisteredScope}, []) ->
    {ok, []};
verify_resowner_scope(#resowner{scope = []}, _Scope) ->
    {error, invalid_scope};
verify_resowner_scope(#resowner{scope = RegisteredScope}, Scope) ->
    case oauth2_priv_set:is_subset(oauth2_priv_set:new(Scope), 
                                   oauth2_priv_set:new(RegisteredScope)) of
        true ->
            {ok, Scope};
        false ->
            {error, badscope}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            {error, notfound};
        [{_Key, Value}] ->
            {ok, Value}
    end.

put(Table, Key, Value) ->
    ets:insert(Table, {Key, Value}).

delete(Table, Key) ->
    ets:delete(Table, Key).

new_request_id() ->
    RequestId = oauth2_token:generate([]),
    case get(?REQUEST_TABLE, RequestId) of
        {ok, _} ->
            new_request_id();
        {error, _} ->
            RequestId
    end.
        