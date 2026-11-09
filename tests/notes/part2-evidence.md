# Nguyên liệu Phần 2 — Đạt, Nam

Đây là ghi chú bằng chứng và dàn ý, không phải bản văn báo cáo để nộp.
`CONTRIBUTING.md` và `docs/report/README.md` yêu cầu nhóm tự viết báo cáo.

## Bàn giao

- Kịch bản: `tests/ACCEPTANCE_PLAN.md`.
- Kiểm thử: `tests/test_acceptance.py`, service core hiện tại; không có HTTP.
- Attack runner: `python tests/attack.py`, xuất `tests/results/attacks.xml`.
- Kết quả đầy đủ: `tests/results/acceptance.xml` (gồm test Part 1).
- Số liệu: `tests/results/tokens.csv`, `aes.csv`, `samples.json`.
- Môi trường và phương pháp: `tests/results/metadata.json`.
- So sánh có nguồn: `tests/COMPARISON.md`.
- Ba biểu đồ: token-size.png, verify-time.png, aes-throughput.png trong `tests/results/`.
- Prototype Ed25519: chưa thực hiện (hạng mục tùy chọn); không có số liệu so sánh HMAC/Ed25519.

## Dàn ý gợi ý cho 1,5 trang Đánh giá (nhóm tự diễn đạt)

1. Khoảng 1/3 trang: threat model và kiểm thử. Người tấn công giữ token Read,
   biết file ID, sửa token hoặc tự nối caveat nhưng không có root key. Giải
   thích các ca pass theo ma trận quyền, thu hồi cả hậu duệ, hết hạn đúng
   tại now=expiry. Nêu rõ số ca riêng Part 2 và toàn bộ suite, tránh cộng
   thành số tình huống tấn công độc lập hoặc chứng minh an toàn tuyệt đối.
2. Khoảng 1/2 trang: kích thước token, latency verify. Dùng hai biểu đồ đầu,
   trích CSV ở 1/20/50 caveat. 21–50 chỉ là thư viện với grammar hợp lệ;
   ứng dụng từ chối >20. Core verify gồm decode, HMAC, parse và đánh giá;
   library verify chỉ decode, HMAC, syntax. Đừng so hai đường như cùng workload.
3. Khoảng 1/3 trang: AES-GCM. Trích biểu đồ thứ ba, nói rõ Python cryptography,
   overhead cố định cho file nhỏ, MiB/s theo plaintext; blob cộng 12 nonce +
   16 tag. Điểm lớn nhất có blob đúng 1 MiB. Không có JSON UTF-8/browser/I/O
   trong thời gian đo; không suy diễn thành throughput HTTP hoặc frontend.
4. Phần còn lại: tradeoff so ACL/JWT/S3, ưu thế attenuation và chi phí state
   cho thu hồi. Nêu điều chưa đo: HTTP, WebCrypto, tải đồng thời, mạng, I/O,
   persistence/concurrency của store, Ed25519, giới hạn bộ nhớ, rò token/XSS.

## Cách đọc số liệu

Mỗi điểm có 5 warmup rồi 31 mẫu × 50 lần; kết quả là median của thời gian
trung bình mỗi batch (không phải median latency request). Raw samples giúp
xem dao động; không có confidence interval hay đảm bảo tail latency. Một
lần chạy trên một máy chưa đủ kết luận tổng quát. Không đo tạo token trong
latency verify. Khóa chỉ sinh trong RAM, không ghi vào kết quả.

## Checklist tích hợp của Phần 3

- Chạy lại test qua API thật và trình duyệt khi có web layer.
- Kiểm tra headers, status/error mapping, nonce mới, fragment và log.
- Chạy lại benchmark trên máy demo; giữ cả metadata và CSV tương ứng.
- Tự viết đoạn Đánh giá, chọn 2–3 biểu đồ và ghi chú phạm vi bên dưới hình.
- Leader review trước khi merge; thay đổi docs cần Phong review.
