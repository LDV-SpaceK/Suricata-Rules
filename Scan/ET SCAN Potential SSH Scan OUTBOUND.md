## ET SCAN Potential SSH Scan OUTBOUND

* Rules:

`alert tcp $HOME_NET any -> $EXTERNAL_NET 22 (msg:"ET SCAN Potential SSH Scan OUTBOUND"; flow:to_server; flags:S,12; threshold: type threshold, track by_src, count 5, seconds 120; reference:url,en.wikipedia.org/wiki/Brute_force_attack; reference:url,doc.emergingthreats.net/2003068; classtype:attempted-recon; sid:2003068; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)`

* Chế độ: alert
* Giao thức: tcp
* $HOME_NET: mạng nhà(thường là các dải mạng private)
* any: tất cả
* EXTERNAL_NET: mạng ngoài(các dải ip public)
* 22: port 22
* flow: to_server: là chiều đi từ $HOME_NET đến $EXTERNAL_NET
* flag: S: cờ SYN
* threshold: type threshold
* track by_src: theo dõi bằng source ip
* count 5: 5 gói tin
* seconds: 120 giây
* reference: tham chiếu
* classtype:attempted-recon: phân loại hành vi cố gắng recon
* sid: mã định danh của rule
* rev: 7: đã bị sửa 6 lần

* Kết luận: rule này sẽ lên alert nếu có 5 gói tin SYN trong vòng 120 giây đi chiều từ trong mạng private ra ngoài public tại cổng 22 dịch vụ SSH, có thể đây là hành vi scan bất hợp pháp từ trong nội bộ ra ngoài
