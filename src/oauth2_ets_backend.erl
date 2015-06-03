%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc OAuth2 backend functions.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(oauth2_ets_backend).

-behaviour(oauth2_backend).

%%% API
-export([add_client/4,
         add_resowner/2, 
         add_resowner/3, 
         delete_client/1, 
         delete_resowner/1,
         create/0, 
         delete/0 
        ]).

%%% OAuth2 backend functionality
-export([authenticate_user/2, 
         authenticate_client/2, 
         associate_access_code/3, 
         associate_access_token/3,
         associate_refresh_token/3, 
         resolve_access_code/2, 
         resolve_access_token/2, 
         resolve_refresh_token/2, 
         revoke_access_code/2, 
         revoke_access_token/2, 
         revoke_refresh_token/2, 
         get_client_identity/2, 
         get_redirection_uri/2,  
         verify_redirection_uri/3, 
         verify_client_scope/3,
         verify_resowner_scope/3, 
         verify_scope/3
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
          client_secret :: binary() | undefined,
          redirect_uri  :: binary(),
          scope         :: [binary()]
         }).

-record(resowner, {
          username  :: binary(),
          password  :: binary(),
          scope     :: scope()
         }).

-type scope()    :: oauth2:scope().


%%%===================================================================
%%% API
%%%===================================================================

-spec add_client(Id, Secret, RedirectURI, Scope) -> ok when
    Id          :: binary(),
    Secret      :: binary() | undefined,
    RedirectURI :: binary(),
    Scope       :: [binary()].
add_client(Id, Secret, RedirectURI, Scope) ->
    put(?CLIENT_TABLE, Id, #client{client_id = Id,
                                   client_secret = Secret,
                                   redirect_uri = RedirectURI,
                                   scope = Scope
                                  }),
    ok.

-spec add_resowner(Username, Password) -> ok when
    Username :: binary(),
    Password :: binary().
add_resowner(Username, Password) ->
    add_resowner(Username, Password, []),
    ok.

-spec add_resowner(Username, Password, Scope) -> ok when
    Username  :: binary(),
    Password  :: binary(),
    Scope     :: [binary()].
add_resowner(Username, Password, Scope) ->
    put(?USER_TABLE, Username, #resowner{username = Username, 
                                         password = Password, scope = Scope}),
    ok.


-spec create() -> ok.
create() ->
    lists:foreach(fun(Table) ->
                          ets:new(Table, [named_table, public])
                  end,
                  ?TABLES),
    ok.

-spec delete() -> ok.
delete() ->
    lists:foreach(fun ets:delete/1, ?TABLES),
    ok.

-spec delete_resowner(Username) -> ok when
    Username :: binary().
delete_resowner(Username) ->
    delete(?USER_TABLE, Username),
    ok.

-spec delete_client(Id) -> ok when
    Id :: binary().
delete_client(Id) ->
    delete(?CLIENT_TABLE, Id),
    ok.

%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

authenticate_user({Username, Password}, AppContext) ->
    case get(?USER_TABLE, Username) of
        {ok, #resowner{password = Password} = Identity} ->
            {ok, {AppContext, Identity}};
        {ok, #resowner{password = _WrongPassword}} ->
            {error, badpass};
        _ ->
            {error, notfound}
    end.

authenticate_client({ClientId, ClientSecret}, AppContext) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, #client{client_secret = ClientSecret} = Identity} ->
            {ok, {AppContext, Identity}};
        {ok, #client{client_secret = _WrongSecret}} ->
            {error, badsecret};
        _ ->
            {error, notfound}
    end.

associate_access_code(AccessCode, Context, AppContext) ->
    put(?ACCESS_CODE_TABLE, AccessCode, Context),
    {ok, AppContext}.

associate_access_token(AccessToken, Context, AppContext) ->
    put(?ACCESS_TOKEN_TABLE, AccessToken, Context),
    {ok, AppContext}.

associate_refresh_token(RefreshToken, Context, AppContext) ->
    put(?REFRESH_TOKEN_TABLE, RefreshToken, Context),
    {ok, AppContext}.

resolve_access_code(AccessCode, AppContext) ->
    case get(?ACCESS_CODE_TABLE, AccessCode) of
        {ok, Grant} ->
            {ok, {AppContext, Grant}};
        Error = {error, notfound} ->
            Error
    end.

resolve_access_token(AccessToken, AppContext) ->
    case get(?ACCESS_TOKEN_TABLE, AccessToken) of
        {ok, Grant} ->
            {ok, {AppContext, Grant}};
        Error = {error, notfound} ->
            Error
    end.

resolve_refresh_token(RefreshToken, AppContext) ->
    case get(?REFRESH_TOKEN_TABLE, RefreshToken) of
        {ok, Grant} ->
            {ok, {AppContext, Grant}};
        Error = {error, notfound} ->
            Error
    end.

%% @doc Revokes an access code AccessCode, so that it cannot be used again.
revoke_access_code(AccessCode, AppContext) ->
    delete(?ACCESS_CODE_TABLE, AccessCode),
    {ok, AppContext}.

%% Not implemented yet.
revoke_access_token(_AccessToken, _AppContext) ->
    {error, notfound}.

%% Not implemented yet.
revoke_refresh_token(_RefreshToken, _AppContext) ->
    {error, notfound}.

get_redirection_uri(ClientId, AppContext) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, #client{redirect_uri = RedirectUri}} ->
            {ok, {AppContext, RedirectUri}};
        {error, notfound} ->
            {error, notfound}
    end.

get_client_identity(ClientId, AppContext) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, Identity} ->
            {ok, {AppContext, Identity}};
        {error, notfound} ->
            {error, notfound}
    end.

verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, undefined,
                       AppContext) ->
    {ok, AppContext};
verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, <<>>,
                       AppContext) ->
    {ok, AppContext};
verify_redirection_uri(#client{redirect_uri = <<>>}, _Uri,
                       _AppContext) ->
    {error, baduri};
verify_redirection_uri(#client{redirect_uri = RegisteredUri}, RegisteredUri,
                       AppContext) ->
    {ok, AppContext};
verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, _DifferentUri,
                       _AppContext) ->
    {error, baduri}.

verify_client_scope(#client{scope = RegisteredScope}, Scope, AppContext) ->
    verify_scope(RegisteredScope, Scope, AppContext).

verify_resowner_scope(#resowner{scope = RegisteredScope}, Scope, AppContext) ->
    verify_scope(RegisteredScope, Scope, AppContext).

verify_scope(RegisteredScope, undefined, AppContext) ->
    {ok, {AppContext, RegisteredScope}};
verify_scope(_RegisteredScope, [], AppContext) ->
    {ok, {AppContext, []}};
verify_scope([], _Scope, _AppContext) ->
    {error, invalid_scope};
verify_scope(RegisteredScope, Scope, AppContext) ->
    case oauth2_priv_set:is_subset(oauth2_priv_set:new(Scope), 
                                   oauth2_priv_set:new(RegisteredScope)) of
        true ->
            {ok, {AppContext, Scope}};
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
