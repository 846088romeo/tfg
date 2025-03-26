#!/bin/bash

BUILD="../genAnBx/src/gsm_attacktrace_passive/build.xml"

echo $BUILD

rm GSM_AttackTrace_passive_roleM.txt GSM_AttackTrace_passive_roleB.txt GSM_AttackTrace_passive_roleI.txt GSM_AttackTrace_passive_roleH.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_M >> GSM_AttackTrace_passive_roleM.txt &
ant -buildfile $BUILD ROLE_B >> GSM_AttackTrace_passive_roleB.txt &
ant -buildfile $BUILD ROLE_I >> GSM_AttackTrace_passive_roleI.txt &
ant -buildfile $BUILD ROLE_H >> GSM_AttackTrace_passive_roleH.txt &
