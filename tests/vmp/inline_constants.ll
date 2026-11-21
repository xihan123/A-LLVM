; Keep aggregate instructions for the translator even in the O2 pipeline.
define i64 @inline_store(ptr %out, i64 %marker) #0 {
  store [17 x i8] zeroinitializer, ptr %out, align 1
  %result = add i64 %marker, 37
  ret i64 %result
}

define i64 @inline_insert(ptr %out, i64 %marker) #0 {
  %aggregate = insertvalue [3 x i64] zeroinitializer, i64 %marker, 1
  %other = insertvalue [3 x i64] %aggregate, i64 1234605616436508552, 0
  %tail = extractvalue [3 x i64] %aggregate, 2
  store [3 x i64] %aggregate, ptr %out, align 1
  %aggregate_live = extractvalue [3 x i64] %aggregate, 1
  %next = getelementptr i8, ptr %out, i64 24
  store [3 x i64] %other, ptr %next, align 1
  %other_live = extractvalue [3 x i64] %other, 0
  %last = getelementptr i8, ptr %out, i64 48
  store i64 %tail, ptr %last, align 1
  %live_out = getelementptr i8, ptr %out, i64 56
  store i64 %aggregate_live, ptr %live_out, align 1
  %other_out = getelementptr i8, ptr %out, i64 64
  store i64 %other_live, ptr %other_out, align 1
  %result = add i64 %marker, 19
  ret i64 %result
}

define i64 @inline_extract(ptr %out, i64 %marker) #0 {
  %value = extractvalue [31 x i8] zeroinitializer, 30
  store i8 %value, ptr %out, align 1
  %result = add i64 %marker, 29
  ret i64 %result
}

attributes #0 = { noinline optnone }
