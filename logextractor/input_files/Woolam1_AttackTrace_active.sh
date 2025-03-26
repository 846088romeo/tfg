#!/bin/bash

BUILD="../genAnBx/src/woolam1_attacktrace_active/build.xml"

echo $BUILD

rm Woolam1_AttackTrace_active_roleB.txt Woolam1_AttackTrace_active_roleI.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_B >> Woolam1_AttackTrace_active_roleB.txt &
ant -buildfile $BUILD ROLE_I >> Woolam1_AttackTrace_active_roleI.txt &
