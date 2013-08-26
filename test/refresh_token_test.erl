%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(refresh_token_test).

-include_lib("eunit/include/eunit.hrl").

-define(PATH, "/refresh_token").
-define(STATE, whatever).
-define(CLIENT1_ID, "Id1").
-define(CLIENT1_SECRET, "Secret1").
-define(CLIENT1_URI, "Uri1").
-define(CLIENT1_SCOPE, [<<"root.a">>, <<"root.b.*">>]).
-define(USER1_USERNAME, "User1").
-define(USER1_PASSWORD, "Password1").
-define(REFRESH_TOKEN, "REFRESHTOKEN").
-define(TOKEN_CODE, "TOKENCODE").
-define(BASIC_CREDENTIALS(ID, SECRET), "Basic " ++ 
            base64:encode_to_string(ID ++ ":" ++ SECRET)).
-define(AUTHENTICATE_REALM, "oauth2_webmachine").
-define(EXPIRY_ABSOLUTE, 1000).

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
    meck:expect(oauth2_token, generate, fun(_) -> <<?REFRESH_TOKEN>> end),
    oauth2_ets_backend:start(),
    oauth2_ets_backend:add_client(<<?CLIENT1_ID>>, <<?CLIENT1_SECRET>>, 
                                  <<?CLIENT1_URI>>, ?CLIENT1_SCOPE),
    oauth2_ets_backend:add_resowner(<<?USER1_USERNAME>>, <<?USER1_PASSWORD>>),
    meck:expect(oauth2_token, generate, fun(_) -> <<?REFRESH_TOKEN>> end),
    {ok, Authorization1} = oauth2:authorize_code_request(<<?CLIENT1_ID>>,
                                                         <<?CLIENT1_URI>>,
                                                         <<?USER1_USERNAME>>,
                                                         <<?USER1_PASSWORD>>,
                                                         ?CLIENT1_SCOPE,
                                                         none),
    oauth2:issue_token_and_refresh(Authorization1, none),
    meck:expect(oauth2_token, generate, fun(_) -> <<?TOKEN_CODE>> end),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:delete_resowner(?USER1_USERNAME),
    oauth2_ets_backend:delete_client(?CLIENT1_ID),
    oauth2_ets_backend:stop(),
    meck:unload(oauth2_token),
    meck:unload(oauth2_config),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

invalid_request_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"refresh_token", ?REFRESH_TOKEN}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)}]),
    {Result1, Response1, State1}  = refresh_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)}]),
    {Result2, Response2, State2}  = refresh_token:process_get(Request2, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_request\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(<<"{\"error\":\"invalid_request\"}">>, 
                   wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2)
    ].

unsupported_grant_type_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"refresh_token", ?REFRESH_TOKEN}],
                                      [{"Authorization",
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)}]),
    {Result1, Response1, State1}  = refresh_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"unsupported_grant_type\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

invalid_client_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"refresh_token", ?REFRESH_TOKEN}],
                                      []),
    {Result1, Response1, State1}  = refresh_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"refresh_token", ?REFRESH_TOKEN}],
                                      [{"Authorization", "foo"}]),
    {Result2, Response2, State2} = refresh_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"refresh_token", ?REFRESH_TOKEN}],
                                      [{"Authorization", 
                                              ?BASIC_CREDENTIALS(?CLIENT1_ID, 
                                                                 "")
                                              }]),
    {Result3, Response3, State3} = refresh_token:process_get(Request3, ?STATE),
    Request4 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"refresh_token", ?REFRESH_TOKEN}],
                                      [{"Authorization",
                                        ?BASIC_CREDENTIALS("foo",
                                                           ?CLIENT1_SECRET)
                                        }]),
    {Result4, Response4, State4} = refresh_token:process_get(Request4, ?STATE),
    Request5 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"client_id=", ?CLIENT1_ID},
                                       {"refresh_token", ?REFRESH_TOKEN}], []),
    {Result5, Response5, State5} = refresh_token:process_get(Request5, ?STATE),
    Request6 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"client_secret=", ?CLIENT1_SECRET},
                                       {"refresh_token", ?REFRESH_TOKEN}], []),
    {Result6, Response6, State6} = refresh_token:process_get(Request6, ?STATE),
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

invalid_grant_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"refresh_token", "foo"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result1, Response1, State1} = refresh_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

invalid_scope_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"refresh_token", ?REFRESH_TOKEN},
                                       {"scope", "root.a.2"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result1, Response1, State1}  = refresh_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_scope\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

successful_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"refresh_token", ?REFRESH_TOKEN}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result1, Response1, State1} = refresh_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"client_id", "foo"},
                                       {"client_secret", "foo"},
                                       {"refresh_token", ?REFRESH_TOKEN},
                                       {"scope", "root.a root.b.*"}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result2, Response2, State2} = refresh_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "refresh_token"},
                                       {"client_id", ?CLIENT1_ID},
                                       {"client_secret", ?CLIENT1_SECRET},
                                       {"refresh_token", ?REFRESH_TOKEN},
                                       {"scope", "root.b.1"}],
                                      []),
    {Result3, Response3, State3} = refresh_token:process_get(Request3, ?STATE),
    [?_assertEqual({halt, 200}, Result1),
     ?_assertEqual(<<"{\"access_token\":\"", ?TOKEN_CODE, "\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,",
                    "\"scope\":\"root.a root.b.*\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 200}, Result2),
     ?_assertEqual(<<"{\"access_token\":\"", ?TOKEN_CODE, "\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,", 
                    "\"scope\":\"root.a root.b.*\"}">>, wrq:resp_body(
                     Response2)),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 200}, Result3),
     ?_assertEqual(<<"{\"access_token\":\"", ?TOKEN_CODE, "\",",
                     "\"token_type\":\"bearer\",\"expires_in\":3600,",
                     "\"scope\":\"root.b.1\"}">>, 
                   wrq:resp_body(Response3)),
     ?_assertEqual(?STATE, State3)
    ].
