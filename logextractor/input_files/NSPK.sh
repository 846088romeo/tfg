#!/bin/bash

BUILD="../genAnBx/src/nspk/build.xml"

echo $BUILD

rm NSPK_roleA.txt NSPK_roleB.txt 

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_B >> NSPK_roleB.txt &
ant -buildfile $BUILD ROLE_A >> NSPK_roleA.txt &
