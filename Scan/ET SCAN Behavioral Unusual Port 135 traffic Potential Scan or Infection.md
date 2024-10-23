## ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection

* Rules:

`alert tcp $HOME_NET any -> any 135 (msg:"ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 70 , seconds 60; metadata: former_category SCAN; reference:url,doc.emergingthreats.net/2001581; classtype:misc-activity; sid:2001581; rev:15; metadata:created_at 2010_07_30, updated_at 2017_05_11;)`

* Rule này sẽ hiện alert nếu phát hiện lưu lượng TCP SYN từ một địa chỉ ip private đến bất kì ip nào tại port 135 với tần suất 70 gói tin trong vòng 60 giây
* Có thể gợi ý một hoạt động quét cổng hoặc phần mềm độc hại cố gắng khai thác dịch vụ RPC/DCOM
