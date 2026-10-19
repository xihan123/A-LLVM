package sample;

import io.github.xihan123.dex2c.annotation.dex2c;
import java.lang.reflect.Method;
import java.util.*;
import java.util.function.IntUnaryOperator;

class Parent { int value(int x) { return x + 11; } }
class Aa { }
class BB { }

class MethodOnly {
    @dex2c static IntUnaryOperator selected(int offset) { return n -> n + offset; }
    static int untouched() { return 123; }
}

@dex2c
interface Defaults {
    default int defaultValue(int x) { return x * 7; }
    static int staticValue(int x) { return x - 2; }
    default IntUnaryOperator callbackDefault(int n) { return x -> x + n; }
}

@dex2c
class Logic extends Parent implements Defaults {
    private int value = 3;
    private static volatile long total = 7;
    int work(int x) { value += x; total += value; return super.value(value) + new Parent().value(x); }
    long math(int a,long b,float f,double d,byte small,short medium,char c,boolean flag) {
        int v = ((a*31+small-medium)^c) >>> (a&63);
        long w = ((b*17-Long.MIN_VALUE) ^ (b >> a)) + (b << (a+32));
        return v + w + (int)f + (long)d + (flag?1:0) + (byte)a + (short)b + (char)a;
    }
    long division(long n,long d) { return n/d + n%d; }
    int division(int n,int d) { return n/d + n%d; }
    double floating(double x,float y) { return x%y + (x-y)*(x+y)/(x==0?1:x); }
    double conversions(int x,long y) { return (double)x + (float)y + (float)x + (double)y; }
    int compares(double x,float y) { return (x<y?-1:x>y?1:0) + (x==y?17:0); }
    int arrays() {
        int[] a={1,2,3};long[] b={Long.MIN_VALUE,9};float[] c={2.5f};double[] d={3.5};
        boolean[] z={true,false};byte[] by={-128,127};char[] ch={'\uffff'};short[] sh={-32768};
        a[1]+=4;b[1]++;c[0]*=2;d[0]/=2;z[1]=z[0];by[1]++;ch[0]++;sh[0]--;
        String[][][] object=new String[2][1][2];object[1][0][1]="array";
        int[][][] primitive=new int[2][3][4];primitive[1][2][3]=9;
        return a[1]+(int)b[1]+(int)c[0]+(int)d[0]+(z[1]?1:0)+by[1]+ch[0]+sh[0]+object[1][0][1].length()+primitive[1][2][3];
    }
    Object identity(Object a) { Object b=a; return b; }
    boolean distinctTypes() { return Aa.class != (Object)BB.class && new Aa() instanceof Aa && new BB() instanceof BB; }
    boolean interned() { return "hello\u0000\ud83d\ude00" == "hello\u0000\ud83d\ude00".intern(); }
    String text(int x,Object item) { return "value="+x+",item="+item+",char="+(char)x; }
    IntUnaryOperator callback(int offset) { return v -> v + offset + value; }
    Runnable anonymous(List<Integer> out) { return new Runnable() { public void run() { out.add(value); } }; }
    int exceptions(Object[] a,Object value) {
        try {
            a[0]=value;
            if(a.length==1)throw new IllegalArgumentException("expected");
            return ((String)a[0]).length();
        } catch(ArrayStoreException e) { return 31; }
        catch(IllegalArgumentException e) { return e.getMessage().length(); }
        catch(NullPointerException|ClassCastException e) { return -7; }
        finally { this.value++; }
    }
    boolean exceptionIdentity(RuntimeException supplied) {
        try { throw supplied; } catch(RuntimeException caught) { return supplied==caught; }
    }
    int reflected(ClassLoader loader) throws Exception {
        Class<?> type=Class.forName("sample.Parent",true,loader);
        Object object=type.getDeclaredConstructor().newInstance();
        Method m=type.getDeclaredMethod("value",int.class);m.setAccessible(true);
        return (Integer)m.invoke(object,8);
    }
    int synchronizedBlock(Object lock,boolean fail) {
        synchronized(lock) { if(fail)throw new IllegalStateException("lock");return ++value; }
    }
    synchronized int next() { return ++value; }
    int references(int count) {
        int n=0;
        for(int i=0;i<count;i++) {String x=new String(new char[]{'a','b'});n+=x.length();}
        return n;
    }
    int recurse(int n) { return n<1?1:n*recurse(n-1); }
    int switches(int x) { switch(x){case 1:return 11;case 2:return 22;case 3:return 33;default:return -1;} }
    int sparse(int x) { switch(x){case -99:return 5;case 56789:return 6;default:return 7;} }
}

public class Run {
    static void check(boolean result) { if(!result)throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        Logic logic=new Logic();
        java.util.concurrent.CountDownLatch ready=new java.util.concurrent.CountDownLatch(8);
        java.util.concurrent.CountDownLatch start=new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<Throwable> failure=new java.util.concurrent.atomic.AtomicReference<>();
        Thread[] firstUse=new Thread[8];
        for(int i=0;i<firstUse.length;i++) {
            firstUse[i]=new Thread(()->{
                ready.countDown();
                try { start.await(); check(logic.recurse(6)==720); }
                catch(Throwable error) { failure.compareAndSet(null,error); }
            });
            firstUse[i].start();
        }
        ready.await(); start.countDown();
        for(Thread thread:firstUse)thread.join();
        if(failure.get()!=null)throw new AssertionError(failure.get());
        check("sample/Aa".hashCode()=="sample/BB".hashCode() && logic.distinctTypes());
        check(MethodOnly.selected(6).applyAsInt(5)==11 && MethodOnly.untouched()==123);
        check(logic.defaultValue(6)==42 && Defaults.staticValue(9)==7 && logic.callbackDefault(11).applyAsInt(6)==17);
        check(logic.conversions(-7,-13)==-40.0);
        check(logic.compares(-9,2)==-1 && logic.compares(9,2)==1 && logic.compares(2,2)==17);
        check(logic.compares(Double.NaN,2)==0);
        boolean trace=Boolean.getBoolean("dex2c.trace");
        int work=logic.work(9),arrays=logic.arrays(),recursion=logic.recurse(7),references=logic.references(12000);
        if(trace)System.out.println("parts="+work+","+arrays+","+recursion+","+references);
        long checksum=work+arrays+recursion+references;
        for(int x:new int[]{0,1,-1,31,32,63,Integer.MIN_VALUE,Integer.MAX_VALUE}) {
            long math=logic.math(x,Long.MIN_VALUE+x,Float.NaN,Double.POSITIVE_INFINITY,(byte)x,(short)x,(char)x,true);
            if(trace)System.out.println("math="+x+":"+math);
            checksum+=math;
            checksum+=logic.switches(x)+logic.sparse(x);
        }
        check(logic.division(Integer.MIN_VALUE,-1)==Integer.MIN_VALUE);
        check(logic.division(Long.MIN_VALUE,-1)==Long.MIN_VALUE);
        try{logic.division(1,0);throw new AssertionError();}catch(ArithmeticException expected){}
        check(Double.isNaN(logic.floating(Double.NaN,1f)));
        Object identity=new Object();check(logic.identity(identity)==identity);check(logic.interned());
        check(logic.text(65,"x").equals("value=65,item=x,char=A"));
        checksum+=logic.callback(6).applyAsInt(8);
        List<Integer> list=new ArrayList<>();logic.anonymous(list).run();checksum+=list.get(0);
        checksum+=logic.exceptions(new String[2],1)+logic.exceptions(new Object[1],"ok")+logic.exceptions(null,"x");
        check(logic.exceptionIdentity(new IllegalStateException("identity")));
        checksum+=logic.reflected(Run.class.getClassLoader());
        Object lock=new Object();try{logic.synchronizedBlock(lock,true);}catch(IllegalStateException expected){}
        checksum+=logic.synchronizedBlock(lock,false);
        Thread[] workers=new Thread[4];
        for(int i=0;i<workers.length;i++){workers[i]=new Thread(()->{for(int j=0;j<250;j++)logic.next();});workers[i].start();}
        for(Thread thread:workers)thread.join();
        checksum+=logic.next();
        check(!java.lang.reflect.Modifier.isNative(Logic.class.getDeclaredMethod("work",int.class).getModifiers()));
        System.out.println("semantic-result="+checksum);
    }
}
