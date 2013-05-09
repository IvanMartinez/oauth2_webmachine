%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(authorization_code_test).

-include_lib("eunit/include/eunit.hrl").
-include("../include/oauth2_wrq.hrl").
-include("../include/oauth2_request.hrl").

-define(PATH, "/authorization_code").
-define(STATE, whatever).
-define(CLIENT1ID, "Id1").
-define(CLIENT1URI, "Uri1").
-define(CLIENT1SCOPE, [<<"root.a">>, <<"root.b.*">>]).
-define(REQUEST1ID, "REQUEST1ID").
-define(STATEPARAM, "State").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Config) -> [invalid_request_tests(Config),
                         unsupported_response_type_tests(Config),
                         successful_tests(Config)
                        ] end
    }.

before_tests() ->
    meck:new(oauth2_config),
    meck:expect(oauth2_config, backend, fun() -> oauth2_ets_backend end),
    meck:expect(oauth2_config, expiry_time, fun(_) -> 3600 end),
    meck:new(oauth2_token),
    meck:expect(oauth2_token, generate, fun() -> <<?REQUEST1ID>> end),
    oauth2_ets_backend:start(),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:stop(),
    meck:unload(oauth2_token),
    meck:unload(oauth2_config),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

invalid_request_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"client_id", ?CLIENT1ID},
                                       {"scope", "root.a.b"}], []),
    {Result1, _Response1, State1} = authorization_code:process_get(Request1, 
                                                                  ?STATE),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"scope", "root.b.c"}], []),
    {Result2, _Response2, State2} = authorization_code:process_get(Request2, 
                                                                  ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(?STATE, State2)
    ].

unsupported_response_type_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "password"},
                                       {"client_id", ?CLIENT1ID}],
                                      []),
    {Result1, _Response1, State1}  = authorization_code:process_get(Request1, 
                                                                   ?STATE),
    [?_assertEqual({halt, 400}, Result1),
     ?_assertEqual(?STATE, State1)
    ].

successful_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT1ID}],
                                      []),
    {Result1, _Response1, State1}  = authorization_code:process_get(Request1, 
                                                                   ?STATE),
    {ok, StoredRequest1} = oauth2_ets_backend:retrieve_request(<<?REQUEST1ID>>),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT1ID},
                                       {"redirect_uri", ?CLIENT1URI},
                                       {"scope", "root.a root.b.*"},
                                       {"state", ?STATEPARAM}],
                                      []),
    {Result3, _Response3, State3}  = authorization_code:process_get(Request3, 
                                                                   ?STATE),
    {ok, StoredRequest3} = oauth2_ets_backend:retrieve_request(<<?REQUEST1ID>>),
    [?_assertEqual({halt, 200}, Result1),
     ?_assertEqual(?STATE, State1),
     ?_assertEqual(#oauth2_request{client_id = <<?CLIENT1ID>>, 
                                   redirect_uri = undefined, scope = undefined, 
                                   state = undefined}, StoredRequest1),
     ?_assertEqual({halt, 200}, Result3),
     ?_assertEqual(?STATE, State3),
     ?_assertEqual(#oauth2_request{client_id = <<?CLIENT1ID>>, 
                                   redirect_uri = <<?CLIENT1URI>>, 
                                   scope = ?CLIENT1SCOPE, 
                                   state = <<?STATEPARAM>>}, StoredRequest3)
    ].
