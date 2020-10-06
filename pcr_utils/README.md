
# PCR Read and Extend

Reads PCR value

```bash
root@tpm-a:~/pcr_utils# go run main.go --mode=read --pcr=23 -v 10 -alsologtostderr

I1006 12:22:28.485244   10509 main.go:66] ======= Print PCR  ========
I1006 12:22:28.487989   10509 main.go:71] PCR(23) 536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c
```


Increments PCR value

```bash
root@tpm-a:~/pcr_utils# go run main.go --mode=extend --pcr=23 -v 10 -alsologtostderr

I1006 12:22:33.498722   10542 main.go:74] ======= Extend PCR  ========
I1006 12:22:33.501522   10542 main.go:79] Current PCR(23) 536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c
I1006 12:22:33.505490   10542 main.go:92] New PCR(23) 9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30
```