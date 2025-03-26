#!/bin/bash

BUILD="../genAnBx/src/fresh_from_a_secret_attacktrace_active/build.xml"

echo $BUILD

rm Fresh_From_A_Secret_AttackTrace_active_roleI.txt Fresh_From_A_Secret_AttackTrace_active_roleA.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_I >> Fresh_From_A_Secret_AttackTrace_active_roleI.txt &
ant -buildfile $BUILD ROLE_A >> Fresh_From_A_Secret_AttackTrace_active_roleA.txt &
