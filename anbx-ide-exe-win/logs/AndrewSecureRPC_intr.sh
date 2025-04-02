#!/bin/bash

BUILD="../genAnBx/src/andrewsecurerpc_intr/build.xml"

echo $BUILD

rm AndrewSecureRPC_intr_ROLE_B.txt AndrewSecureRPC_intr_ROLE_intr.txt AndrewSecureRPC_intr_ROLE_A.txt

ant -buildfile $BUILD runinit

ant -buildfile $BUILD ROLE_B >> AndrewSecureRPC_intr_ROLE_B.txt &
ant -buildfile $BUILD ROLE_intr >> AndrewSecureRPC_intr_ROLE_intr.txt &
ant -buildfile $BUILD ROLE_A >> AndrewSecureRPC_intr_ROLE_A.txt &
