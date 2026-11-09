# Kịch bản kiểm thử theo đặc tả v1 — Phần 2 (Đạt, Nam)

Nguồn: `docs/spec/api-spec.md`, nhất là §3–5. Kiểm thử độc lập với HTTP:
hiện repository chỉ có service Python, chưa có Flask routes. Mã HTTP dưới
đây là hợp đồng cần kiểm tra lại khi lớp web hoàn tất, không phải HTTP đã đo.
Mỗi ca dùng FileStore tạm riêng, file A/B riêng và đồng hồ cố định.

| Thao tác | Read | Edit | Full Control |
|---|---|---|---|
| Đọc nội dung mã hóa | Cho phép | Cho phép | Cho phép |
| Thay nội dung (không xóa đối tượng file) | 403 forbidden | Cho phép | Cho phép |
| Chia sẻ Read | Cho phép | Cho phép | Cho phép |
| Chia sẻ Edit | 400 bad_request | Cho phép | Cho phép |
| Chia sẻ Full | 400 bad_request | 400 bad_request | Cho phép |
| Thu hồi share đã cấp | 403 forbidden | 403 forbidden | Cho phép |
| Xóa đối tượng file | 403 forbidden | 403 forbidden | Cho phép |

`test_permission_matrix` kiểm tra 12 tổ hợp đọc/sửa/thu hồi/xóa; ca bị từ
chối phải giữ nguyên dữ liệu và token mục tiêu. `test_share_matrix` kiểm tra
9 tổ hợp chia sẻ, và hạn của token con không vượt hạn thực tế của cha.
Upload không yêu cầu token; Edit được thay toàn bộ nội dung nhưng không xóa
file. Full được ủy quyền Full theo đặc tả hiện tại.

| ID | Thiết lập và hành động | Kết quả mong đợi | Tự động hóa |
|---|---|---|---|
| A01 | Chủ upload, cấp Read, đọc lại | Nội dung đúng, permission đúng | permission_matrix |
| A02 | Thay chữ ký thành 32 byte zero | invalid_token | hostile_tokens/signature |
| A03 | Dùng token A truy cập file B đang tồn tại | invalid_token | hostile_tokens/wrong_file |
| A04 | Xóa từng caveat, giữ chữ ký cũ | invalid_token | remove_each_caveat |
| A05 | Đổi caveat Read thành Full | invalid_token | hostile_tokens/edit |
| A06 | Đảo thứ tự caveat | invalid_token | hostile_tokens/reorder |
| A07 | Người giữ Read tự nối op=edit/full (không root key) | Vẫn Read, sửa bị cấm | append_cannot_escalate |
| A08 | now = expiry-1, expiry, expiry+1 | Cho phép, expired, expired | expiry_boundary |
| A09 | Thu hồi cha; thử cha, con, nhánh độc lập, chủ | Cha/con revoked; nhánh/chủ còn dùng | revocation_cascades_only_to_descendants |
| A10 | Nối caveat ngoài grammar với chữ ký hợp lệ | invalid_token | hostile_tokens/unknown |
| A11 | Tính lại HMAC bằng hashlib/hmac, không helper thư viện | Chữ ký giống nhau | independent_hmac |
| A12 | Hơn 20 caveat hoặc hơn 4096 ký tự | invalid_token | hostile_tokens/too_many,too_long |
| A13 | Mọi quyền × thao tác | Theo ma trận trên | permission_matrix,share_matrix |
| A14 | Biết ID file nhưng thiếu/rác token | missing_token/invalid_token | guessed_id_without_capability |

Các tình huống đoán ID chỉ chứng minh ID không thay thế capability; không
chứng minh không tồn tại oracle về sự tồn tại của file. Không có thử vét cạn
mạng hay tuyên bố độ an toàn mật mã từ số lượng ca pass.

Khi có HTTP: chạy lại cùng kịch bản qua client, kiểm tra status/error JSON,
Authorization, giới hạn body, no-store/no-referrer, không rò token trong log.
Kiểm tra trình duyệt riêng: fragment không gửi tới server, AES-GCM đúng định
dạng nonce||ciphertext||tag, nonce mới sau edit, sai tag/key phải giải mã lỗi.
