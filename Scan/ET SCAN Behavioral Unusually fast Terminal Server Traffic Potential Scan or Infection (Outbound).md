## ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Outbound)

* Rule

`alert tcp $HOME_NET any -> $EXTERNAL_NET 3389 (msg:"ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Outbound)"; flow:to_server; flags: S,12; threshold: type both, track by_src, count 20, seconds 360; metadata: former_category SCAN; reference:url,threatpost.com/en_us/blogs/new-worm-morto-using-rdp-infect-windows-pcs-082811; classtype:misc-activity; sid:2013479; rev:5; metadata:created_at 2011_08_29, updated_at 2017_05_11;)`

* Quy tắc Suricata/IDS này được sử dụng để phát hiện lưu lượng bất thường từ mạng nội bộ ($HOME_NET) ra bên ngoài ($EXTERNAL_NET) trên cổng 3389, thường được sử dụng cho Remote Desktop Protocol (RDP)

* Quy tắc này nhằm phát hiện các hành vi bất thường liên quan đến lưu lượng RDP, thường thấy trong các cuộc tấn công quét hoặc lây nhiễm mã độc, như một dấu hiệu cảnh báo sớm để bảo vệ hệ thống khỏi các mối đe dọa tiềm ẩn.
