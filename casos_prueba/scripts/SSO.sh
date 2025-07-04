#!/bin/bash

BUILD="../genAnBx/src/sso/build.xml"

echo $BUILD

rm SSO_role*

ant -buildfile $BUILD runinit 

ant -buildfile $BUILD ROLE_idp >> SSO_roleidp.txt &
ant -buildfile $BUILD ROLE_SP >> SSO_roleSP.txt &
ant -buildfile $BUILD ROLE_C >> SSO_roleC.txt &
