#!/bin/bash

BUILD="../genAnBx/src/andrewsecurerpc_attacktrace_active/build.xml"

echo $BUILD

rm AndrewSecureRPC_AttackTrace_active_role*

ant -buildfile $BUILD ROLE_B >> AndrewSecureRPC_AttackTrace_active_roleB.txt &
ant -buildfile $BUILD ROLE_I >> AndrewSecureRPC_AttackTrace_active_roleI.txt &
ant -buildfile $BUILD ROLE_A >> AndrewSecureRPC_AttackTrace_active_roleA.txt &
