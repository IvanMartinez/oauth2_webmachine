%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(authorization_token_form_test).

-include_lib("eunit/include/eunit.hrl").

-define(PATH, "/authorization_form").
-define(CONTEXT, whatever).
-define(USER1USERNAME, "User1").
-define(USER1PASSWORD, "Password1").
-define(USER1SCOPE, [<<"a.*">>, <<"b">>]).
-define(CLIENT1ID, "Client1Id").
-define(CLIENT1URI, "Uri1").
-define(REQUEST1ID, "Request1ID").
-define(REQUEST1CLIENTID, ?CLIENT1ID).
-define(REQUEST1URI, ?CLIENT1URI).
-define(REQUEST1SCOPE, undefined).
-define(REQUEST1STATE, undefined).
-define(REQUEST2ID, "Request2ID").
-define(REQUEST2CLIENTID, ?CLIENT1ID).
-define(REQUEST2URI, ?CLIENT1URI).
-define(REQUEST2SCOPE, [<<"a.b">>]).
-define(REQUEST2STATE, "State2").
-define(REQUEST3ID, "Request5ID").
-define(REQUEST3CLIENTID, ?CLIENT1ID).
-define(REQUEST3URI, ?CLIENT1URI).
-define(REQUEST3SCOPE, [<<"foo">>]).
-define(REQUEST3STATE, undefined).
-define(REQUEST4ID, "Request6ID").
-define(REQUEST4CLIENTID, ?CLIENT1ID).
-define(REQUEST4URI, ?CLIENT1URI).
-define(REQUEST4SCOPE, [<<"foo">>]).
-define(REQUEST4STATE, "State6").
-define(TOKENCODE, "TOKENCODE").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Config) -> [bad_request_tests(Config),
                         request_timeout_tests(Config),
                         invalid_scope_tests(Config),
                         access_denied_tests(Config),
                         successful_tests(Config)
                        ] end
    }.

before_tests() ->
    meck:new(oauth2_config),
    meck:expect(oauth2_config, backend, fun() -> oauth2_ets_backend end),
    meck:expect(oauth2_config, expiry_time, fun(_) -> 3600 end),
    meck:expect(oauth2_config, token_generation, fun() -> oauth2_token end),
    meck:new(oauth2_token),
    oauth2_ets_backend:start(),
    oauth2_ets_backend:add_client(<<?CLIENT1ID>>, <<>>, <<?CLIENT1URI>>, 
                                  []),
    oauth2_ets_backend:add_resowner(<<?USER1USERNAME>>, <<?USER1PASSWORD>>,
                                    ?USER1SCOPE),
    meck:expect(oauth2_token, generate, fun(_) -> <<?REQUEST1ID>> end),
    oauth2_ets_backend:store_request(<<?REQUEST1CLIENTID>>, <<?REQUEST1URI>>, 
                                     ?REQUEST1SCOPE, ?REQUEST1STATE),
    meck:expect(oauth2_token, generate, fun(_) -> <<?REQUEST2ID>> end),
    oauth2_ets_backend:store_request(<<?REQUEST2CLIENTID>>, <<?REQUEST2URI>>, 
                                     ?REQUEST2SCOPE, <<?REQUEST2STATE>>),
    meck:expect(oauth2_token, generate, fun(_) -> <<?REQUEST3ID>> end),
    oauth2_ets_backend:store_request(<<?REQUEST3CLIENTID>>, <<?REQUEST3URI>>, 
                                     ?REQUEST3SCOPE, ?REQUEST3STATE),
    meck:expect(oauth2_token, generate, fun(_) -> <<?REQUEST4ID>> end),
    oauth2_ets_backend:store_request(<<?REQUEST4CLIENTID>>, <<?REQUEST4URI>>, 
                                     ?REQUEST4SCOPE, <<?REQUEST4STATE>>),
    meck:expect(oauth2_token, generate, fun(_) -> <<?TOKENCODE>> end),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:delete_resowner(?USER1USERNAME),
    oauth2_ets_backend:delete_client(?CLIENT1ID),
    oauth2_ets_backend:stop(),
    meck:unload(oauth2_token),
    meck:unload(oauth2_config),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

bad_request_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result1, _Response1, Context1} = authorization_token_form:process_get(
                                                                    Request1, 
                                                                    ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"password", ?USER1PASSWORD}], []),
    {Result2, _Response2, Context2} = authorization_token_form:process_get(
                                                                    Request2, 
                                                                    ?CONTEXT),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"username", ?USER1USERNAME}], []),
    {Result3, _Response3, Context3} = authorization_token_form:process_get(
                                                                    Request3, 
                                                                    ?CONTEXT),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(?CONTEXT, Context2),
     ?_assertEqual({halt, 400}, Result3),
     ?_assertEqual(?CONTEXT, Context3)
    ].

request_timeout_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", "foo"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result1, _Response1, Context1} = authorization_token_form:process_get(
                                                                      Request1,
                                                                      ?CONTEXT),
    [?_assertEqual({halt, 408}, Result1),
     ?_assertEqual(?CONTEXT, Context1)
    ].

invalid_scope_tests(_Config) ->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST3ID},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result1, Response1, Context1} = authorization_token_form:process_get(
                                                                     Request1,
                                                                     ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST4ID},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result2, Response2, Context2} = authorization_token_form:process_get(
                                                                     Request2,
                                                                     ?CONTEXT),
    [?_assertEqual({halt, 302}, Result1),
     ?_assertEqual(?REQUEST3URI ++"?error=invalid_scope", 
                   wrq:get_resp_header("Location", Response1)),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 302}, Result2),
     ?_assertEqual(?REQUEST3URI ++"?error=invalid_scope&state=" ++ 
                       ?REQUEST4STATE, 
                   wrq:get_resp_header("Location", Response2)),
     ?_assertEqual(?CONTEXT, Context2)
    ].

access_denied_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"username", ?USER1USERNAME},
                                       {"password", "foo"}], []),
    {Result1, Response1, Context1} = authorization_token_form:process_get(
                                                                      Request1,
                                                                      ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST2ID},
                                       {"username", "foo"},
                                       {"password", ?USER1PASSWORD}], []),
    {Result2, Response2, Context2} = authorization_token_form:process_get(
                                                                     Request2,
                                                                     ?CONTEXT),
    [?_assertEqual({halt, 302}, Result1),
     ?_assertEqual(?REQUEST1URI ++"?error=access_denied", 
                   wrq:get_resp_header("Location", Response1)),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 302}, Result2),
     ?_assertEqual(?REQUEST2URI ++"?error=access_denied&state=" ++ 
                       ?REQUEST2STATE,
                   wrq:get_resp_header("Location", Response2)),
     ?_assertEqual(?CONTEXT, Context2)
    ].

successful_tests(_Config) ->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result1, Response1, Context1} = authorization_token_form:process_get(
                                                                     Request1,
                                                                     ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST2ID},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result2, Response2, Context2} = authorization_token_form:process_get(
                                                                    Request2, 
                                                                    ?CONTEXT),
    [?_assertEqual({halt, 302}, Result1),
     ?_assertEqual(?REQUEST1URI ++ "?access_token=" ++ ?TOKENCODE ++
                       "&token_type=bearer&expires_in=3600&scope=a.* b", 
                   wrq:get_resp_header("Location", Response1)),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 302}, Result2),
     ?_assertEqual(?REQUEST2URI ++ "?access_token=" ++ ?TOKENCODE ++
                       "&token_type=bearer&expires_in=3600&scope=a.b&state=" ++ 
                       ?REQUEST2STATE, 
                   wrq:get_resp_header("Location", Response2)),
     ?_assertEqual(?CONTEXT, Context2)
    ].
