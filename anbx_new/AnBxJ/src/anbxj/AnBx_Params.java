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

import java.io.Serializable;
import java.util.Arrays;

/**
 * AnBx Params: implements a tuple as an array of serializable objects
 */
public class AnBx_Params implements Serializable {

    /**
     * Unique identifier for serialisation.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Default layer for AnBx_Params.
     */
    private static final AnBx_Layers layer = AnBx_Layers.LANGUAGE;

    /**
     * Array of objects containing AnBx parameters.
     */
    private Object[] v;

    /**
     * AnBx_Params constructor
     * @param obj an array of objects
     */
    public AnBx_Params(Object... obj) {
        // Build the object and make the structure "flat"
        // ([obj1,obj2,[obj3,obj4]] -> [obj1,obj2,obj3,obj4] )
        int size = calcSize(obj);
        v = new Object[size];
        flatten(obj, 0);
        this.info();
    }

    private int calcSize(Object... obj) {
        int size = 0;
        for (Object o : obj) {
            if (o instanceof AnBx_Params) {
                size += ((AnBx_Params) o).size();
            } else {
                size++;
            }
        }
        return size;
    }

    private int flatten(Object[] obj, int startIndex) {
        int index = startIndex;
        for (Object o : obj) {
            if (o instanceof AnBx_Params) {
                index = flatten(((AnBx_Params) o).v, index);
            } else {
                v[index++] = o;
            }
        }
        return index;
    }

    /**
     * Retrieve an object from the array of AnBx parameters
     * @param i the numerical index
     * @return the object corresponding to the index
     */
    public Object getValue(int i) {
        if (i >= 0 && i < v.length) {
            return v[i];
        } else {
            AnBx_Debug.out(layer, "AnBx_Params - error - size: " + this.size() + " i: " + i);
            return null;
        }
    }

    /**
     * Reset the array of objects to null
     */
    public void reset() {
        Arrays.fill(v, null);
    }

    /**
     * Get the size of the array of objects
     * @return the length of the array of objects
     */
    public int size() {
        return v.length;
    }

    @Override
    public String toString() {
        return "AnBx_Params [v=" + Arrays.toString(v) + "]";
    }

    @Override
    public int hashCode() {
        return 31 + Arrays.hashCode(v);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        AnBx_Params other = (AnBx_Params) obj;
        return Arrays.equals(v, other.v);
    }

    private void info() {
        AnBx_Debug.out(layer, "AnBx_Params - size: " + this.size());
        AnBx_Debug.out(layer, "AnBx_Params - hash: " + this.hashCode());
        AnBx_Debug.out(layer, "AnBx_Params - params: " + this.toString());
    }
}
