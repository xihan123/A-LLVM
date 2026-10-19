package io.github.xihan123.dex2c.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public record MethodKey(String owner, String name, String descriptor) implements Comparable<MethodKey> {
    public String id() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(toString().getBytes(StandardCharsets.UTF_8))).substring(0, 24);
        } catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    public String symbol() { return "d2c_" + id(); }
    public String bridge() {
        long value=Long.parseUnsignedLong(id().substring(0,14),16);
        String alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuilder name=new StringBuilder();
        do {name.append(alphabet.charAt((int)(value%52)));value/=52;} while(value!=0);
        return name.toString();
    }
    @Override public String toString() { return owner + "." + name + descriptor; }
    @Override public int compareTo(MethodKey other) { return toString().compareTo(other.toString()); }
}
