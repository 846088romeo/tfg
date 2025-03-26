#!/bin/bash

BUILD="../genAnBx/src/gsm/build.xml"

echo $BUILD

rm GSM_roleM.txt GSM_roleB.txt GSM_roleH.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_M >> GSM_roleM.txt &
ant -buildfile $BUILD ROLE_B >> GSM_roleB.txt &
ant -buildfile $BUILD ROLE_H >> GSM_roleH.txt &
