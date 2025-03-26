#!/bin/bash

BUILD="../genAnBx/src/nspk_attacktrace_passive/build.xml"

echo $BUILD


ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_s >> NSPK_attacktrace_passive_roles.txt &
ant -buildfile $BUILD ROLE_B >> NSPK_attacktrace_passive_roleB.txt &
ant -buildfile $BUILD ROLE_I >> NSPK_attacktrace_passive_roleI.txt &
ant -buildfile $BUILD ROLE_A >> NSPK_attacktrace_passive_roleA.txt &
