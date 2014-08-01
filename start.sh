#!/bin/sh
cd `dirname $0`
exec erl -pa $PWD/ebin $PWD/deps/*/ebin -boot start_sasl -s reloader -s oauth2_webmachine -config $PWD/priv/oauth2_webmachine.config -name oauth2_webmachine
