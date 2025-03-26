#!/bin/bash

BUILD="../genAnBx/src/andrewsecurerpc/build.xml"

echo $BUILD

rm AndrewSecureRPC_roleB.txt AndrewSecureRPC_roleA.txt

ant -buildfile $BUILD ROLE_B >> AndrewSecureRPC_roleB.txt &
ant -buildfile $BUILD ROLE_A >> AndrewSecureRPC_roleA.txt &
