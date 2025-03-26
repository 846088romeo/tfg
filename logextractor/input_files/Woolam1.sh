#!/bin/bash

BUILD="../genAnBx/src/woolam1/build.xml"

echo $BUILD

rm Woolam1_roles.txt Woolam1_roleB.txt Woolam1_roleA.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_s >> Woolam1_roles.txt &
ant -buildfile $BUILD ROLE_B >> Woolam1_roleB.txt &
ant -buildfile $BUILD ROLE_A >> Woolam1_roleA.txt &
