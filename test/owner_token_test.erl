%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Tests owner_token.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(owner_token_test).

-include_lib("eunit/include/eunit.hrl").

-define(PATH, "/owner_token").
-define(STATE, whatever).
-define(USER1USERNAME, "User1").
-define(USER1PASSWORD, "Password1").
-define(USER1SCOPE, [<<"root.a.*">>, <<"root.x.y">>]).
-define(TOKENCODE, "TOKENCODE").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Config) -> [invalid_request_tests(Config),
                         unsupported_grant_type_tests(Config),
                         invalid_grant_tests(Config),
                         invalid_scope_tests(Config),
                         successful_tests(Config)
                        ] end
    }.

before_tests() ->
    meck:new(oauth2_config),
    meck:expect(oauth2_config, backend, fun() -> oauth2_ets_backend end),
    meck:expect(oauth2_config, expiry_time, fun(_) -> 3600 end),
    meck:expect(oauth2_config, token_generation, fun() -> oauth2_token end),
    meck:new(oauth2_token),
    meck:expect(oauth2_token, generate, fun(_) -> <<?TOKENCODE>> end),
    oauth2_ets_backend:start(),
    oauth2_ets_backend:add_resowner(<<?USER1USERNAME>>, <<?USER1PASSWORD>>,
                                ?USER1SCOPE),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:delete_resowner(?USER1USERNAME),
    oauth2_ets_backend:stop(),
    meck:unload(oauth2_token),
    meck:unload(oauth2_config),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

invalid_request_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.a.b"}], []),
    {Result1, Response1, State1}  = owner_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.x.y"}], []),
    {Result2, Response2, State2}  = owner_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"scope", "root.a.c"}], []),
    {Result3, Response3, State3}  = owner_token:process_get(Request3, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_request\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(<<"{\"error\":\"invalid_request\"}">>, 
                   wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 400}, Result3),
     ?_assertEqual(<<"{\"error\":\"invalid_request\"}">>, 
                   wrq:resp_body(Response3)),
     ?_assertEqual(?STATE, State3)
    ].

unsupported_grant_type_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "scope1"}], []),
    {Result1, Response1, State1}  = owner_token:process_get(Request1, ?STATE),
    [?_assertEqual(Result1, {halt, 400}),
     ?_assertEqual(<<"{\"error\":\"unsupported_grant_type\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(State1, ?STATE)
    ].

invalid_grant_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", "foo"}], []),
    {Result1, Response1, State1}  = owner_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", "foo"},
                                       {"password", ?USER1PASSWORD}], []),
    {Result2, Response2, State2}  = owner_token:process_get(Request2, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>,
                   wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2)
    ].

invalid_scope_tests(_Config) ->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.x.x"}], []),
    {Result1, Response1, State1}  = owner_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_scope\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

successful_tests(_Config) ->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result1, Response1, State1}  = owner_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.a.a"}], []),
    {Result2, Response2, State2}  = owner_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.a.b root.x.y"}], []),
    {Result3, Response3, State3}  = owner_token:process_get(Request3, ?STATE),
    [?_assertEqual({halt, 200}, Result1),
     ?_assertEqual(<<"{\"access_token\":\"TOKENCODE\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,",
                    "\"scope\":\"root.a.* root.x.y\"}">>, wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 200}, Result2),
     ?_assertEqual(<<"{\"access_token\":\"TOKENCODE\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,", 
                    "\"scope\":\"root.a.a\"}">>, wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 200}, Result3),
     ?_assertEqual(<<"{\"access_token\":\"TOKENCODE\",",
                     "\"token_type\":\"bearer\",\"expires_in\":3600,",
                     "\"scope\":\"root.a.b root.x.y\"}">>, 
                   wrq:resp_body(Response3)),
     ?_assertEqual(?STATE, State3)
    ].
