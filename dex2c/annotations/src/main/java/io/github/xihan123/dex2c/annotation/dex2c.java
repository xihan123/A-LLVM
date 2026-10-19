package io.github.xihan123.dex2c.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 将方法实现（或类内的方法实现）下沉到 JNI；默认 VMP，可显式选择 NATIVE + CSE。 */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface dex2c {
    ProtectionMode mode() default ProtectionMode.VMP;
}
