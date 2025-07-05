#!/bin/bash

BUILD="../genAnBx/src/andrewsecurerpc_i/build.xml"

echo $BUILD

rm AndrewSecureRPC_I_role*

ant -buildfile $BUILD runinit


ant -buildfile $BUILD ROLE_B >> AndrewSecureRPC_I_roleB.txt &
ant -buildfile $BUILD ROLE_I >> AndrewSecureRPC_I_roleI.txt &
ant -buildfile $BUILD ROLE_A >> AndrewSecureRPC_I_roleA.txt &
