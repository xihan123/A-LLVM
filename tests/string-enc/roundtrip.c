/* roundtrip.c — 字符串加密强化（-irobf-cse-perkey）的语义往返样本。
 *
 * 打印一个已知明文串。开启 perkey 后，该串在编译期被 ChaCha8 加密进
 * .AProtect.rodata，运行期由注入的 ndkp_cse_decode 还原。若编码器（pass 编译期
 * C++）与解码器（发射的运行期 IR）的 ChaCha8/SplitMix64 不一致，输出即为乱码。
 * 故「运行本程序、比对 stdout == 明文」是这一镜像的兜底。见 roundtrip.sh。
 */
#include <stdio.h>

int main(void) {
	const char *s = "NDKP_ROUNDTRIP_secret_2b7f";
	printf("%s\n", s);
	return 0;
}
