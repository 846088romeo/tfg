#!/bin/bash

BUILD="../genAnBx/src/nspk_attacktrace_active/build.xml"

echo $BUILD

rm NSPK_attacktrace_active_roleB.txt NSPK_attacktrace_active_roleI.txt NSPK_attacktrace_active_roleA.tx

ant -buildfile $BUILD compile

ant -buildfile $BUILD ROLE_B >> NSPK_attacktrace_active_roleB.txt &
ant -buildfile $BUILD ROLE_I >> NSPK_attacktrace_active_roleI.txt &
ant -buildfile $BUILD ROLE_A >> NSPK_attacktrace_active_roleA.txt &
