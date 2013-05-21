%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(client_token_test).

-include_lib("eunit/include/eunit.hrl").

-define(PATH, "/client_token").
-define(STATE, whatever).
-define(CLIENT1ID, "Id1").
-define(CLIENT1SECRET, "Secret1").
-define(CLIENT1SCOPE, [<<"root.a">>, <<"root.b.*">>]).
-define(TOKENCODE, "TOKENCODE").
-define(BASIC_CREDENTIALS(ID, SECRET), "Basic " ++ 
            base64:encode_to_string(ID ++ ":" ++ SECRET)).
-define(AUTHENTICATE_REALM, "oauth2_webmachine").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Config) -> [invalid_request_tests(Config),
                         unsupported_grant_type_tests(Config),
                         invalid_client_tests(Config),
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
    oauth2_ets_backend:add_client(<<?CLIENT1ID>>, <<?CLIENT1SECRET>>, <<>>, 
                                  ?CLIENT1SCOPE),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:delete_client(?CLIENT1ID),
    oauth2_ets_backend:stop(),
    meck:unload(oauth2_token),
    meck:unload(oauth2_config),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

invalid_request_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"scope", "root.a.b"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1ID,
                                                           ?CLIENT1SECRET)}]),
    {Result1, Response1, State1}  = client_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_request\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

unsupported_grant_type_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"scope", "root.a"}],
                                      [{"Authorization",
                                        "Basic " ++
                                            base64:encode_to_string("ID1:P1")}]),
    {Result1, Response1, State1}  = client_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"unsupported_grant_type\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

invalid_client_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"},
                                       {"scope", "root.b.2"}],
                                      []),
    {Result1, Response1, State1}  = client_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"}],
                                      [{"Authorization", "foo"}]),
    {Result2, Response2, State2} = client_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"}],
                                      [{"Authorization", 
                                              ?BASIC_CREDENTIALS(?CLIENT1ID, "")
                                              }]),
    {Result3, Response3, State3} = client_token:process_get(Request3, ?STATE),
    Request4 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"}],
                                      [{"Authorization", 
                                              ?BASIC_CREDENTIALS("foo",
                                                                 ?CLIENT1SECRET)
                                              }]),
    {Result4, Response4, State4} = client_token:process_get(Request4, ?STATE),
    Request5 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"},
                                       {"client_id=", ?CLIENT1ID},
                                       {"scope", "root.a"}], []),
    {Result5, Response5, State5} = client_token:process_get(Request5, ?STATE),
    Request6 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"},
                                       {"client_secret=", ?CLIENT1SECRET}], []),
    {Result6, Response6, State6} = client_token:process_get(Request6, ?STATE),
    [?_assertEqual({halt, 401}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_client\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual("Basic realm=\"" ++ ?AUTHENTICATE_REALM ++ "\"", 
                   wrq:get_resp_header("WWW-Authenticate", Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 401}, Result2),
     ?_assertEqual(<<"{\"error\":\"invalid_client\"}">>, 
                   wrq:resp_body(Response2)),
     ?_assertEqual("Basic realm=\"" ++ ?AUTHENTICATE_REALM ++ "\"", 
                   wrq:get_resp_header("WWW-Authenticate", Response2)),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 401}, Result3),
     ?_assertEqual(<<"{\"error\":\"invalid_client\"}">>, 
                   wrq:resp_body(Response3)),
     ?_assertEqual("Basic realm=\"" ++ ?AUTHENTICATE_REALM ++ "\"", 
                   wrq:get_resp_header("WWW-Authenticate", Response3)),
     ?_assertEqual(?STATE, State3),
     ?_assertEqual({halt, 401}, Result4),
     ?_assertEqual(<<"{\"error\":\"invalid_client\"}">>, 
                   wrq:resp_body(Response4)),
     ?_assertEqual("Basic realm=\"" ++ ?AUTHENTICATE_REALM ++ "\"", 
                   wrq:get_resp_header("WWW-Authenticate", Response4)),
     ?_assertEqual(?STATE, State4),
     ?_assertEqual({halt, 401}, Result5),
     ?_assertEqual(<<"{\"error\":\"invalid_client\"}">>, 
                   wrq:resp_body(Response5)),
     ?_assertEqual("Basic realm=\"" ++ ?AUTHENTICATE_REALM ++ "\"", 
                   wrq:get_resp_header("WWW-Authenticate", Response5)),
     ?_assertEqual(?STATE, State5),
     ?_assertEqual({halt, 401}, Result6),
     ?_assertEqual(<<"{\"error\":\"invalid_client\"}">>, 
                   wrq:resp_body(Response6)),
     ?_assertEqual("Basic realm=\"" ++ ?AUTHENTICATE_REALM ++ "\"", 
                   wrq:get_resp_header("WWW-Authenticate", Response6)),
     ?_assertEqual(?STATE, State6)
    ].

invalid_scope_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"},
                                       {"scope", "root.a.2"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1ID,
                                                           ?CLIENT1SECRET)
                          }]),
    {Result1, Response1, State1}  = client_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_scope\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

successful_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1ID,
                                                           ?CLIENT1SECRET)
                          }]),
    {Result1, Response1, State1}  = client_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"},
                                       {"client_id", "foo"},
                                       {"client_secret", "foo"},
                                       {"scope", "root.b.a"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1ID,
                                                           ?CLIENT1SECRET)
                          }]),
    {Result2, Response2, State2}  = client_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "client_credentials"},
                                       {"client_id", ?CLIENT1ID},
                                       {"client_secret", ?CLIENT1SECRET},
                                       {"scope", "root.a root.b.*"}],
                                      []),
    {Result3, Response3, State3}  = client_token:process_get(Request3, ?STATE),
    [?_assertEqual({halt, 200}, Result1),
     ?_assertEqual(<<"{\"access_token\":\"TOKENCODE\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,",
                    "\"scope\":\"root.a root.b.*\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 200}, Result2),
     ?_assertEqual(<<"{\"access_token\":\"TOKENCODE\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,", 
                    "\"scope\":\"root.b.a\"}">>, wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 200}, Result3),
     ?_assertEqual(<<"{\"access_token\":\"TOKENCODE\",",
                     "\"token_type\":\"bearer\",\"expires_in\":3600,",
                     "\"scope\":\"root.a root.b.*\"}">>, 
                   wrq:resp_body(Response3)),
     ?_assertEqual(?STATE, State3)
    ].
