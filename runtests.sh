#! /bin/bash

DIR=`dirname $0`
BASEDIR=`cd $DIR; pwd`

python "$BASEDIR/tests/test_mochitests.py" "$BASEDIR"
python "$BASEDIR/tests/test_taskhandler.py" "$BASEDIR"
