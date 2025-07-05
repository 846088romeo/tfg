#!/bin/bash

BUILD="../genAnBx/src/sso_i2/build.xml"

echo $BUILD

rm SSO_I2_role*

ant -buildfile $BUILD runinit 

ant -buildfile $BUILD ROLE_idp >> SSO_I2_roleidp.txt &
ant -buildfile $BUILD ROLE_SP >> SSO_I2_roleSP.txt &
ant -buildfile $BUILD ROLE_I >> SSO_I2_roleI.txt &
ant -buildfile $BUILD ROLE_C >> SSO_I2_roleC.txt &
