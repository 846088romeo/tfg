#!/bin/bash

BUILD="../genAnBx/src/isosk2pmap/build.xml"

echo $BUILD

rm ISOSK2PMAP_role*

ant -buildfile $BUILD runinit

ant -buildfile $BUILD ROLE_B >> ISOSK2PMAP_roleB.txt &
ant -buildfile $BUILD ROLE_A >> ISOSK2PMAP_roleA.txt &
