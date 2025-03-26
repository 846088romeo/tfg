#!/bin/bash

BUILD="../genAnBx/src/fresh_from_a_secret/build.xml"

echo $BUILD

rm Fresh_From_A_Secret_roleB.txt Fresh_From_A_Secret_roleA.txt

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_B >> Fresh_From_A_Secret_roleB.txt &
ant -buildfile $BUILD ROLE_A >> Fresh_From_A_Secret_roleA.txt &
