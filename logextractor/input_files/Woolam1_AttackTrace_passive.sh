#!/bin/bash

BUILD="../genAnBx/src/woolam1_attacktrace_passive/build.xml"

echo $BUILD

rm Woolam1_AttackTrace_passive_roles.txt Woolam1_AttackTrace_passive_roleB.txt Woolam1_AttackTrace_passive_roleI.txt  Woolam1_AttackTrace_passive_roleA.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_s >> Woolam1_AttackTrace_passive_roles.txt &
ant -buildfile $BUILD ROLE_B >> Woolam1_AttackTrace_passive_roleB.txt &
ant -buildfile $BUILD ROLE_I >> Woolam1_AttackTrace_passive_roleI.txt &
ant -buildfile $BUILD ROLE_A >> Woolam1_AttackTrace_passive_roleA.txt &
