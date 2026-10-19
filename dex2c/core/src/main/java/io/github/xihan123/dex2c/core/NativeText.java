package io.github.xihan123.dex2c.core;

import org.objectweb.asm.Type;
import java.nio.charset.StandardCharsets;

final class NativeText {
    static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        // JNI names/descriptors use modified UTF-8, including supplementary identifiers.
        for (char c : value.toCharArray()) {
            if (c >= 1 && c < 128) appendByte(out, c);
            else if (c < 2048) { appendByte(out, 0xc0 | (c >> 6)); appendByte(out, 0x80 | (c & 63)); }
            else { appendByte(out, 0xe0 | (c >> 12)); appendByte(out, 0x80 | ((c >> 6) & 63)); appendByte(out, 0x80 | (c & 63)); }
        }
        return out.append('"').toString();
    }
    private static void appendByte(StringBuilder out, int b) {
        if (b >= 32 && b < 127 && b != '"' && b != '\\') out.append((char) b);
        else out.append(String.format("\\%03o", b));
    }
    static String utf16(String value) {
        if (value.isEmpty()) return "nullptr";
        StringBuilder out = new StringBuilder("(const jchar[]){");
        for (int i = 0; i < value.length(); i++) { if (i != 0) out.append(','); out.append((int)value.charAt(i)); }
        return out.append('}').toString();
    }
    static String member(Type type) {
        return switch (type.getSort()) {
            case Type.LONG -> "j"; case Type.FLOAT -> "f"; case Type.DOUBLE -> "d";
            case Type.OBJECT, Type.ARRAY -> "l"; default -> "i";
        };
    }
    static String ctype(Type type) {
        return switch (type.getSort()) {
            case Type.VOID -> "void"; case Type.BOOLEAN -> "jboolean"; case Type.BYTE -> "jbyte";
            case Type.CHAR -> "jchar"; case Type.SHORT -> "jshort"; case Type.INT -> "jint";
            case Type.LONG -> "jlong"; case Type.FLOAT -> "jfloat"; case Type.DOUBLE -> "jdouble";
            default -> "jobject";
        };
    }
}
