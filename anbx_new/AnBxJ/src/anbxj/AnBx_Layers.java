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
 * AnBx Debug/Logging layers.
 */
public enum AnBx_Layers {

    /**
     * AnBx Debug/Logging layer for network-related operations.
     */
    NETWORK,

    /**
     * AnBx Debug/Logging layer for encryption-related operations.
     */
    ENCRYPTION,

    /**
     * AnBx Debug/Logging layer for language-related operations.
     */
    LANGUAGE,

    /**
     * AnBx Debug/Logging layer for session-related operations.
     */
    SESSION,

    /**
     * AnBx Debug/Logging layer for protocol-related operations.
     */
    PROTOCOL,

    /**
     * AnBx Debug/Logging layer for business logic-related operations.
     */
    BUSINESS_LOGIC,

    /**
     * AnBx Debug/Logging layer for application-related operations.
     */
    APPLICATION,

    /**
     * AnBx Debug/Logging layer that is always active.
     */
    ALWAYS,

    /**
     * AnBx Debug/Logging layer for handling exceptions.
     */
    EXCEPTION
}