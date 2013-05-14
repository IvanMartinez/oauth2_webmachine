%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(authorization_form_test).

-include_lib("eunit/include/eunit.hrl").

-define(PATH, "/authorization_form").
-define(STATE, whatever).
-define(USER1USERNAME, "User1").
-define(USER1PASSWORD, "Password1").
-define(USER1SCOPE, [<<"root.a.*">>, <<"root.x.y">>]).
-define(REQUEST1ID, "REQUEST1ID").
-define(REQUEST1CLIENTID, "Client1Id").
-define(REQUEST1URI, undefined).
-define(REQUEST1SCOPE, undefined).
-define(REQUEST1STATE, undefined).
-define(REQUEST2ID, "REQUEST2ID").
-define(REQUEST2CLIENTID, "Client2Id").
-define(REQUEST2URI, "Uri2").
-define(REQUEST2SCOPE, "Scope2").
-define(REQUEST2STATE, "State2").
-define(TOKENCODE, "TOKENCODE").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Config) -> [%bad_request_tests(Config),
                         %unauthorized_tests(Config),
                         %request_timeout_tests(Config)
                         %invalid_scope_tests(Config),
                         %successful_tests(Config)
                        ] end
    }.

before_tests() ->
    meck:new(oauth2_config),
    meck:expect(oauth2_config, backend, fun() -> oauth2_ets_backend end),
    meck:expect(oauth2_config, expiry_time, fun(_) -> 3600 end),
    meck:new(oauth2_token),
    oauth2_ets_backend:start(),
    oauth2_ets_backend:add_user(<<?USER1USERNAME>>, <<?USER1PASSWORD>>,
                                ?USER1SCOPE),
    meck:expect(oauth2_token, generate, fun() -> <<?REQUEST1ID>> end),
    oauth2_ets_backend:store_request(?REQUEST1CLIENTID, ?REQUEST1URI, ?REQUEST1SCOPE, ?REQUEST1STATE),
    meck:expect(oauth2_token, generate, fun() -> <<?REQUEST2ID>> end),
    oauth2_ets_backend:store_request(?REQUEST2CLIENTID, ?REQUEST2URI, ?REQUEST2SCOPE, ?REQUEST2STATE),
    meck:expect(oauth2_token, generate, fun() -> <<?TOKENCODE>> end),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:delete_user(?USER1USERNAME),
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
    {Result1, _Response1, State1}  = authorization_form:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"password", ?USER1PASSWORD}], []),
    {Result2, _Response2, State2}  = authorization_form:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"username", ?USER1USERNAME}], []),
    {Result3, _Response3, State3}  = authorization_form:process_get(Request3, ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(?STATE, State2),
     ?_assertEqual({halt, 400}, Result3),
     ?_assertEqual(?STATE, State3)
    ].

unauthorized_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"username", ?USER1USERNAME},
                                       {"password", "foo"}], []),
    {Result1, _Response1, State1}  = authorization_form:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", ?REQUEST1ID},
                                       {"username", "foo"},
                                       {"password", ?USER1PASSWORD}], []),
    {Result2, _Response2, State2}  = authorization_form:process_get(Request2, ?STATE),
    [?_assertEqual({halt, 401}, Result1),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 401}, Result2),
     ?_assertEqual(?STATE, State2)
    ].

request_timeout_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"request_id", "foo"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD}], []),
    {Result1, _Response1, State1}  = authorization_form:process_get(Request1, ?STATE),
    [?_assertEqual({halt, 408}, Result1),
     ?_assertEqual(?STATE, State1)
    ].

invalid_scope_tests(_Config) ->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.x.x"}], []),
    {Result1, Response1, State1}  = authorization_form:process_get(Request1, ?STATE),
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
    {Result1, Response1, State1}  = authorization_form:process_get(Request1, ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.a.a"}], []),
    {Result2, Response2, State2}  = authorization_form:process_get(Request2, ?STATE),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"grant_type", "password"},
                                       {"username", ?USER1USERNAME},
                                       {"password", ?USER1PASSWORD},
                                       {"scope", "root.a.b root.x.y"}], []),
    {Result3, Response3, State3}  = authorization_form:process_get(Request3, ?STATE),
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
