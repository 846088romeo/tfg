#!/bin/bash

BUILD="../genAnBx/src/sso_replay/build.xml"

echo $BUILD

rm SSO_replay_role*

ant -buildfile $BUILD runinit 

ant -buildfile $BUILD ROLE_idp >> SSO_replay_roleidp.txt &
ant -buildfile $BUILD ROLE_SP >> SSO_replay_roleSP.txt &
ant -buildfile $BUILD ROLE_I >> SSO_replay_roleI.txt &
ant -buildfile $BUILD ROLE_C >> SSO_replay_roleC.txt &
