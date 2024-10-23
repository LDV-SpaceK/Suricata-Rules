## ET DNS Query for .to TLD

`alert dns $HOME_NET any -> any any (msg:"ET DNS Query for .to TLD"; dns_query; content:".to"; endswith; fast_pattern; metadata: former_category DNS; classtype:bad-unknown; sid:2027757; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Minor, created_at 2019_07_26, updated_at 2019_09_28;)`

* alert khi ip mạng nội bộ query đến domain có chứa đuôi .to
* Bản thân tên miền .to không độc hại, nhưng do các quy định đăng ký thoải mái và khả năng ẩn danh cao, nó đã trở thành lựa chọn phổ biến của các đối tượng xấu
