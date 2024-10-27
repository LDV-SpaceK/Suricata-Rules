## ET DNS Query for .cc TLD.md

* Rule

* `alert dns $HOME_NET any -> any any (msg:"ET DNS Query for .cc TLD"; dns_query; content:".cc"; endswith; fast_pattern; metadata: former_category DNS; classtype:bad-unknown; sid:2027758; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_07_26, updated_at 2019_09_28;)`

* Quy tắc Suricata/IDS này được thiết lập để phát hiện các truy vấn DNS từ mạng nội bộ liên quan đến tên miền cấp cao nhất (TLD) .cc. Đây là một TLD thường được sử dụng trong các hoạt động độc hại như tấn công mạng hoặc phát tán phần mềm độc hại

