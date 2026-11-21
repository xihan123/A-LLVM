package sample;

import io.github.xihan123.dex2c.annotation.dex2c;

@dex2c
class PrimitiveLogic {
    Object identity(Object value) { return value; }

    long reuse(Object token, int input, long seed) {
        long result = seed;
        {
            Object value = token;
            Object adjacent = identity(value);
            if (value != adjacent) throw new AssertionError();
        }
        {
            int value = input;
            int adjacent = ~value;
            result += ((value + adjacent) ^ (value * 31)) >>> (input + 32);
        }
        {
            long value = seed;
            long adjacent;
            value = adjacent = (value + input) ^ (value << input);
            result ^= (value * 17) + (adjacent >>> (input - 64));
        }
        {
            Object value = token;
            Object adjacent = identity(value);
            if (value != adjacent) throw new AssertionError();
        }
        return result;
    }

    int exceptionLocal(int input, int divisor, int[] values) {
        int saved = (input * 31) ^ (input + 7);
        try {
            int quotient = input / divisor;
            int length = values.length;
            saved = ~input;
            return quotient + length + saved;
        } catch (ArithmeticException | NullPointerException expected) {
            // saved has no read on the successful path before its overwrite.
            return saved;
        }
    }

    long flow(long seed, int limit) {
        long value = seed;
        int index = 0;
        while (index < limit) {
            long mixed = (value + index) ^ (seed >>> (index - 64));
            if ((index & 1) == 0) value = mixed * 17;
            else value = mixed - seed;
            switch (index & 3) {
                case 0: value ^= 31; break;
                case 1: value += seed; break;
                case 2: value -= index; break;
                default: value |= seed;
            }
            index++;
        }
        switch (limit) {
            case -7: return value ^ 11;
            case 12345: return value + 13;
            default: return value;
        }
    }

    int helperEdges(Object token, int input) {
        int value = input + 17;
        // The next read of value after this helper is IINC (a read and a write).
        new Object();
        value++;
        Object copied = identity(token);
        int length = new int[]{value, input}.length;
        int kind = copied instanceof String ? 3 : 7;
        return (value ^ length) + kind + (copied == token ? 19 : -19);
    }
}

public class Run {
    public static void main(String[] args) {
        PrimitiveLogic logic = new PrimitiveLogic();
        Object token = new Object();
        long checksum = 0;
        for (int input : new int[]{0, 1, -1, 31, 32, 63, 64, -65, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
            long seed = Long.MIN_VALUE + input;
            checksum += logic.reuse(token, input, seed);
            checksum ^= logic.flow(seed, (input & 7) + 1);
            checksum += logic.exceptionLocal(input, 0, new int[3]);
            checksum += logic.exceptionLocal(input, 1, null);
            checksum += logic.exceptionLocal(input, -1, new int[3]);
            checksum += logic.helperEdges(token, input);
            checksum += logic.helperEdges("text", input);
        }
        for (int index = 0; index < 12000; index++) checksum ^= logic.reuse(token, index, index);
        checksum ^= logic.flow(Long.MAX_VALUE, -7);
        System.out.println("primitive-result=" + checksum);
    }
}
