/*

 AnBx Java Security Library

 Copyright 2011-2024 Paolo Modesti
 Copyright 2018-2024 SCM/SCDT/SCEDT, Teesside University
 Copyright 2016-2018 School of Computer Science, University of Sunderland
 Copyright 2013-2015 School of Computing Science, Newcastle University
 Copyright 2011-2012 DAIS, Universita' Ca' Foscari Venezia
   
 This file is part of AnBx

 AnBx is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 any later version.

 AnBx is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with AnBx. If not, see <http://www.gnu.org/licenses/>.

 */

package anbxj;

/**
 * AnBx Channel Mode: A class to store AnBx channel modes.
 * <p>
 * This class represents the mode of an AnBx channel, including the origin agent,
 * destination agent, version agents, and mode flags such as forward (frw) and fresh.
 */
public class AnBx_ChannelMode {

    private AnBx_Agent orig;
    private AnBx_Agent dest;
    private AnBx_Agent[] vers;
    private boolean frw;
    private boolean fresh;

    /**
     * Constructor for AnBx_ChannelMode.
     *
     * @param orig  The origin agent of the channel mode.
     * @param dest  The destination agent of the channel mode.
     * @param vers  The array of version agents.
     * @param frw   Flag indicating if the channel mode is forward.
     * @param fresh Flag indicating if the channel mode is fresh.
     */
    public AnBx_ChannelMode(AnBx_Agent orig, AnBx_Agent dest, AnBx_Agent[] vers, boolean frw, boolean fresh) {
        this.orig = orig;
        this.dest = dest;
        this.vers = vers;
        this.frw = frw;
        this.fresh = fresh;
    }

    /**
     * Get the origin agent of the channel mode.
     *
     * @return The origin agent.
     */
    public AnBx_Agent getOrig() {
        return orig;
    }

    /**
     * Get the destination agent of the channel mode.
     *
     * @return The destination agent.
     */
    public AnBx_Agent getDest() {
        return dest;
    }

    /**
     * Get the array of version agents.
     *
     * @return The array of version agents.
     */
    public AnBx_Agent[] getVers() {
        return vers;
    }

    /**
     * Check if the channel mode is forward.
     *
     * @return True if the channel mode is forward, false otherwise.
     */
    public boolean isFrw() {
        return frw;
    }

    /**
     * Check if the channel mode is fresh.
     *
     * @return True if the channel mode is fresh, false otherwise.
     */
    public boolean isFresh() {
        return fresh;
    }
}
