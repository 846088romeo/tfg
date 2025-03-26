#!/bin/bash

BUILD="../genAnBx/src/gsm_attacktrace_active/build.xml"

echo $BUILD


rm  GSM_AttackTrace_active_roleB.txt GSM_AttackTrace_active_roleI.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_B >> GSM_AttackTrace_active_roleB.txt &
ant -buildfile $BUILD ROLE_I >> GSM_AttackTrace_active_roleI.txt &
