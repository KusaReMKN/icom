# ICOM のやつ

## 注意！

これはその場しのぎのプログラムであって、その構造に欠陥がある。
動作に一切の保証はない。
また、責任もない。

## つかいかた

MikoPBX を収容している Ubuntu において、以下の通り実行する。

```console
# apt update && apt upgrade -y
# apt install clang llvm libelf-dev libbpf-dev
# git clone https://github.com/kusaremkn/icom.git # まだ公開されていない
# cd icom
# vi icom.c # SADDR や DESTPORT の定義を icom の IP アドレスに変える
# make
# ip link set eth0 xdp obj icom.o # これで完了
# ip link set eth0 xdp off # これで元に戻る
```
