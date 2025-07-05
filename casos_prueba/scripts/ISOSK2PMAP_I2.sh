#!/bin/bash

BUILD="../genAnBx/src/isosk2pmap_i2/build.xml"

echo $BUILD

rm ISOSK2PMAP_I2_role*

ant -buildfile $BUILD runinit

ant -buildfile $BUILD ROLE_B >> ISOSK2PMAP_I2_roleB.txt &
ant -buildfile $BUILD ROLE_I >> ISOSK2PMAP_I2_roleI.txt &
ant -buildfile $BUILD ROLE_A >> ISOSK2PMAP_I2_roleA.txt &
