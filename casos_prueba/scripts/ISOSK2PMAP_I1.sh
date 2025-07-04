#!/bin/bash

BUILD="../genAnBx/src/isosk2pmap_i1/build.xml"

echo $BUILD

rm ISOSK2PMAP_I1_role*

ant -buildfile $BUILD runinit

ant -buildfile $BUILD ROLE_B >> ISOSK2PMAP_I1_roleB.txt &
ant -buildfile $BUILD ROLE_I >> ISOSK2PMAP_I1_roleI.txt &
ant -buildfile $BUILD ROLE_A >> ISOSK2PMAP_I1_roleA.txt &
