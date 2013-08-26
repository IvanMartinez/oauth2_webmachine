%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(access_token_test).

-include_lib("eunit/include/eunit.hrl").

-define(PATH, "/access_token").
-define(STATE, whatever).
-define(CLIENT1_ID, "Id1").
-define(CLIENT1_SECRET, "Secret1").
-define(CLIENT1_URI, "Uri1").
-define(CLIENT1_SCOPE, [<<"root.a">>, <<"root.b.*">>]).
-define(USER1_USERNAME, "User1").
-define(USER1_PASSWORD, "Password1").
-define(AUTHORIZATION_CODE1, "AUTHORIZATIONCODE1").
-define(AUTHORIZATION_CODE2, "AUTHORIZATIONCODE2").
-define(AUTHORIZATION_CODE3, "AUTHORIZATIONCODE3").
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
                         successful_tests(Config),
                         revoked_tests(Config)
                        ] end
    }.

before_tests() ->
    meck:new(oauth2_config),
    meck:expect(oauth2_config, backend, fun() -> oauth2_ets_backend end),
    meck:expect(oauth2_config, expiry_time, fun(_) -> 3600 end),
    meck:expect(oauth2_config, token_generation, fun() -> oauth2_token end),
    meck:new(oauth2_token),
    meck:expect(oauth2_token, generate, fun(_) -> <<?AUTHORIZATION_CODE1>> end),
    oauth2_ets_backend:start(),
    oauth2_ets_backend:add_client(<<?CLIENT1_ID>>, <<?CLIENT1_SECRET>>, 
                                  <<?CLIENT1_URI>>, ?CLIENT1_SCOPE),
    oauth2_ets_backend:add_resowner(<<?USER1_USERNAME>>, <<?USER1_PASSWORD>>),
    meck:expect(oauth2_token, generate, fun(_) -> <<?AUTHORIZATION_CODE1>> end),
    {ok, Authorization1} = oauth2:authorize_code_request(<<?CLIENT1_ID>>,
                                                         <<?CLIENT1_URI>>,
                                                         <<?USER1_USERNAME>>,
                                                         <<?USER1_PASSWORD>>,
                                                         ?CLIENT1_SCOPE,
                                                         none),
    oauth2:issue_code(Authorization1, none),
    meck:expect(oauth2_token, generate, fun(_) -> <<?AUTHORIZATION_CODE2>> end),
    {ok, Authorization2} = oauth2:authorize_code_request(<<?CLIENT1_ID>>,
                                                         <<?CLIENT1_URI>>,
                                                         <<?USER1_USERNAME>>,
                                                         <<?USER1_PASSWORD>>,
                                                         ?CLIENT1_SCOPE,
                                                         none),
    oauth2:issue_code(Authorization2, none),
    meck:expect(oauth2_token, generate, fun(_) -> <<?AUTHORIZATION_CODE3>> end),
    {ok, Authorization3} = oauth2:authorize_code_request(<<?CLIENT1_ID>>,
                                                         <<?CLIENT1_URI>>,
                                                         <<?USER1_USERNAME>>,
                                                         <<?USER1_PASSWORD>>,
                                                         ?CLIENT1_SCOPE,
                                                         none),
    oauth2:issue_code(Authorization3, none),
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
                                      [{"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)}]),
    {Result1, Response1, State1}  = access_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)}]),
    {Result2, Response2, State2}  = access_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"code", ?AUTHORIZATION_CODE1}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)}]),
    {Result3, Response3, State3}  = access_token:process_get(Request3, ?STATE),
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
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization",
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)}]),
    {Result1, Response1, State1}  = access_token:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"unsupported_grant_type\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1)
    ].

invalid_client_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      []),
    {Result1, Response1, State1}  = access_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", "foo"}]),
    {Result2, Response2, State2} = access_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                              ?BASIC_CREDENTIALS(?CLIENT1_ID, 
                                                                 "")
                                              }]),
    {Result3, Response3, State3} = access_token:process_get(Request3, ?STATE),
    Request4 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization",
                                        ?BASIC_CREDENTIALS("foo",
                                                           ?CLIENT1_SECRET)
                                        }]),
    {Result4, Response4, State4} = access_token:process_get(Request4, ?STATE),
    Request5 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"client_id=", ?CLIENT1_ID},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}], []),
    {Result5, Response5, State5} = access_token:process_get(Request5, ?STATE),
    Request6 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"client_secret=", ?CLIENT1_SECRET},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}], []),
    {Result6, Response6, State6} = access_token:process_get(Request6, ?STATE),
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
                                      [{"grant_type", "authorization_code"},
                                       {"code", "foo"},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result1, Response1, State1}  = access_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"client_id", ?CLIENT1_ID},
                                       {"client_secret", ?CLIENT1_SECRET},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", "foo"}],
                                      []),
    {Result2, Response2, State2}  = access_token:process_get(Request2, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>,
                   wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2)
    ].

successful_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result1, Response1, State1}  = access_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"client_id", "foo"},
                                       {"client_secret", "foo"},
                                       {"code", ?AUTHORIZATION_CODE2},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result2, Response2, State2}  = access_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"client_id", ?CLIENT1_ID},
                                       {"client_secret", ?CLIENT1_SECRET},
                                       {"code", ?AUTHORIZATION_CODE3},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      []),
    {Result3, Response3, State3}  = access_token:process_get(Request3, ?STATE),
    [?_assertEqual({halt, 200}, Result1),
     ?_assertEqual(<<"{\"access_token\":\"", ?TOKEN_CODE, "\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,",
                    "\"refresh_token\":\"", ?TOKEN_CODE, 
                     "\",\"scope\":\"root.a root.b.*\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 200}, Result2),
     ?_assertEqual(<<"{\"access_token\":\"", ?TOKEN_CODE, "\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,",
                    "\"refresh_token\":\"", ?TOKEN_CODE, 
                     "\",\"scope\":\"root.a root.b.*\"}">>, 
                   wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 200}, Result3),
     ?_assertEqual(<<"{\"access_token\":\"", ?TOKEN_CODE, "\",",
                    "\"token_type\":\"bearer\",\"expires_in\":3600,",
                    "\"refresh_token\":\"", ?TOKEN_CODE, 
                     "\",\"scope\":\"root.a root.b.*\"}">>, 
                   wrq:resp_body(Response3)),
     ?_assertEqual(?STATE, State3)
    ].

revoked_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"code", ?AUTHORIZATION_CODE1},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result1, Response1, State1}  = access_token:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"client_id", "foo"},
                                       {"client_secret", "foo"},
                                       {"code", ?AUTHORIZATION_CODE2},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      [{"Authorization", 
                                        ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                           ?CLIENT1_SECRET)
                          }]),
    {Result2, Response2, State2}  = access_token:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "authorization_code"},
                                       {"client_id", ?CLIENT1_ID},
                                       {"client_secret", ?CLIENT1_SECRET},
                                       {"code", ?AUTHORIZATION_CODE3},
                                       {"redirect_uri", ?CLIENT1_URI}],
                                      []),
    {Result3, Response3, State3}  = access_token:process_get(Request3, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>, 
                   wrq:resp_body(Response1)),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>,
                   wrq:resp_body(Response2)),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 400}, Result3),
     ?_assertEqual(<<"{\"error\":\"invalid_grant\"}">>, 
                   wrq:resp_body(Response3)),
     ?_assertEqual(?STATE, State3)
    ].
