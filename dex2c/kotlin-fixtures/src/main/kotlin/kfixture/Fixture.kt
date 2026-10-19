package kfixture

import io.github.xihan123.dex2c.annotation.dex2c
import kotlin.coroutines.*

@dex2c
object Fixture {
    private var value = 4
    fun call(input: Int): String {
        val callbacks = listOf<(Int) -> Int>({ it + value }, { it * 3 })
        return runCatching { callbacks.sumOf { it(input) }.toString() }
            .getOrElse { "error:${it.javaClass.name}" }
    }
    fun anonymous(): Runnable = object : Runnable { override fun run() { value++ } }
    private suspend fun suspendStep(input: Int): Int = suspendCoroutine { it.resume(input + value) }
    suspend fun stateMachine(input: Int): Int {
        val first = suspendStep(input)
        return suspendStep(first)
    }
    fun runState(): Int {
        var result = -1
        val body: suspend () -> Int = { stateMachine(8) }
        body.startCoroutine(object : Continuation<Int> {
            override val context: CoroutineContext = EmptyCoroutineContext
            override fun resumeWith(value: Result<Int>) { result = value.getOrThrow() }
        })
        return result
    }
}

object InlineBoundary {
    inline fun <reified T> kind(): Class<T> = T::class.java
    inline val answer: Int get() = 42
}

object MethodFixture {
    @dex2c
    fun nested(input: Int): Int {
        val outer = { a: Int -> { b: Int -> input + a + b } }
        return outer(2)(3)
    }

    @dex2c
    fun reference(): (Int) -> Int = ::`named$lambda$reference`

    @JvmStatic
    private fun `named$lambda$reference`(input: Int) = input * 7
}

fun main() {
    check(MethodFixture.nested(4) == 9)
    check(MethodFixture.reference()(3) == 21)
    check(Fixture.call(3) == "16")
    Fixture.anonymous().run()
    check(Fixture.runState() == 18)
    println("kotlin-result=${Fixture.call(3)}:${Fixture.runState()}")
}
