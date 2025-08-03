#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * IPv4 アドレスを構成するためのヘルパマクロ
 */
#define IPv4_ADDR(a, b, c, d) \
	(((((((__be32)(a) << 8) | (b)) << 8) | (c)) << 8) | (d))

/*
 * ペイロードのうち、\r\nSP の SP のインデクスを返す。
 * 見付からなければ -1 を返す。
 */
static int
findCRLFSP(void const *payload, void const *data_end)
{
	int state = 0;

	for (int i = 0; payload + i < data_end && i < 1024; i++) {
		/* \r\n を探す */
		if (*(char *)(payload + i) == "\r\n "[state])
			state++;
		else
			state = 0;
		if (state == 3)
			return i;
	}

	return -1;
}

int SEC("prog")
icom(struct xdp_md *ctx)
{
	/*
	 * (long) は本来 (intptr_t) であるべき。<stdint.h> を #include すると
	 * ヘッダファイルの依存関係でトチるっぽい（えっ？）
	 */
	void * const data = (void *)(long)ctx->data;
	void * const data_end = (void *)(long)ctx->data_end;

	/* Ethernet データフレームより短かかったら何もしない */
	struct ethhdr * const eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* IP ヘッダより短かったら何もしない */
	struct iphdr * const ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* UDP パケットでなければ何もしない */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* UDP パケットより短かったら何もしない */
	struct udphdr * const udp = (struct udphdr *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	/* 関係ない差出人だったら何もしない（ホストオーダ） */
#define SADDR	IPv4_ADDR(172, 20, 222, 1)
	if (ip->saddr != __constant_htonl(SADDR))
		return XDP_PASS;

	/* 関係ないポート宛だったら何もしない（ホストオーダ） */
#define DESTPORT	5060
	if (udp->dest != __constant_htons(DESTPORT))
		return XDP_PASS;

	/*
	 * とりあえずヘッダ行を連結してみる。
	 * XXX: 連結されてほしいヘッダ行は Authorization: の行だが、それより前
	 * に二行に渡るヘッダがある場合にはそれが連結されてしまいそう。まあ、
	 * しょうがないかもね。
	 */
	void * const payload = (void *)(udp + 1);
	int spindex = findCRLFSP(payload, data_end);
	if (spindex < 0)
		return XDP_PASS;
	*(char *)(payload + spindex - 2) = ',';
	*(char *)(payload + spindex - 1) = ' ';

	/* チェックサムをポイする */
	udp->check = 0;

	return XDP_PASS;
}
