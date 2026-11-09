# So sánh cơ chế cấp quyền — ghi chú cho Why/Evaluate

So sánh định tính, không phải benchmark triển khai ACL/JWT/S3. ACL ở đây là
mô hình danh sách principal/quyền theo tài nguyên; ví dụ cụ thể là S3 ACL.
JWT là định dạng token, nên hành vi ủy quyền/thu hồi phụ thuộc ứng dụng.

| Tiêu chí | Macaroon trong demo | ACL truyền thống | JWT ký (JWS) | S3 presigned URL |
|---|---|---|---|---|
| Căn cứ truy cập | Sở hữu token, caveat hợp lệ | Principal/group có grant | Claims đã xác thực + policy ứng dụng | Sở hữu URL ký cho object/method |
| Người nhận cần tài khoản | Không | Thường cần principal; có thể có nhóm public | Không bắt buộc bởi JWT | Không cần AWS credentials |
| Tự thu hẹp quyền bằng credential nhận được | Nối caveat không cần root key | Cập nhật grant qua hệ quản trị | Sửa claims làm mất chữ ký; cần bên phát hành ký lại | Người giữ URL không thể tùy ý ký lại method/expiry |
| Thu hồi | Set share_id, chặn mọi hậu duệ; cần state | Xóa/sửa grant ở server | Cần policy bổ sung, ví dụ denylist jti; RFC không định nghĩa endpoint thu hồi | Hết hạn, credential mất hiệu lực hoặc policy từ chối |
| Hết hạn | Min của tất cả expires | Tùy hệ ACL | exp nếu được dùng, verifier phải kiểm tra | Hạn URL và hạn credentials |
| Chi phí/độ dài | Token tăng theo caveat, chuỗi HMAC | Lookup policy/state | Phụ thuộc claims và thuật toán ký | Chữ ký, query params, policy AWS |
| Rủi ro khi link/token lộ | Bearer có thể bị dùng lại trong quyền hiện có | Tùy cơ chế xác thực principal | Nếu dùng kiểu bearer thì có thể dùng lại | URL là bearer, dùng lại đến hạn |
| Bảo mật nội dung | AES-GCM phía client là cơ chế riêng | Không tự cung cấp mã hóa | JWS không mã hóa payload; JWE là cơ chế khác | URL không tự cung cấp mã hóa phía client |

Nguồn đối chiếu:

- [Bài báo Macaroons](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/): controlled delegation qua contextual caveats.
- [S3 ACL overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html): grant cho account/group và kiểm tra theo tài nguyên. Đây là ví dụ ACL, không đại diện mọi ACL.
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html): JWT/JWS/JWE, exp (§4.1.4), jti (§4.1.7). Denylist là lựa chọn thiết kế ứng dụng, không phải đảm bảo của định dạng.
- [AWS presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html): object/method/expiry, bearer URL, credential validity và giới hạn policy.

Liên hệ Why: theo mô hình của project, macaroon hỗ trợ chia sẻ không tài
khoản và thu hẹp quyền mà không trao root key. API hiện vẫn gọi server để
đăng ký share_id; không nên mô tả toàn bộ luồng chia sẻ là offline. Thu hồi
đã làm hệ thống có state. Không có bằng chứng để kết luận nhanh hơn JWT/ACL/S3.
