/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.utils;

import java.lang.reflect.Array;

/**
 *
 * @author Karol
 */
public class ArrayUtils {
    
    public static byte[] concatenate (byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;

        @SuppressWarnings("unchecked")
        byte[] c = (byte[]) Array.newInstance(a.getClass().getComponentType(), aLen+bLen);
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);

        return c;
    }
    
    public static byte[] parseBytes(String byteLine) {
        String[] byteValues = byteLine
                .substring(1, byteLine.length() - 1)
                .split(",");
        
        byte[] bytes = new byte[byteValues.length];
        
        for (int i=0, len=bytes.length; i<len; i++) {
            bytes[i] = Byte.parseByte(byteValues[i].trim());     
        }
        
        return bytes;
    }
    

}
