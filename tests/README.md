# Phần 2 — Kiểm thử và số liệu (Đạt, Nam)

Thư mục này gom kịch bản kiểm thử, script tấn công cục bộ, benchmark, kết quả
và ghi chú bàn giao. Không thay đổi mã core của Phần 1.

## Đọc theo thứ tự

1. [Kịch bản theo đặc tả](ACCEPTANCE_PLAN.md): ma trận Read/Edit/Full và kết quả mong đợi.
2. [Phát hiện pentest](PENTEST_FINDINGS.md): ba lỗi đã tái hiện, điều kiện ảnh hưởng và hướng sửa cho Phần 1.
3. [Ghi chú bàn giao](notes/part2-evidence.md): nguyên liệu và dàn ý để Phần 3 tự viết Đánh giá.
4. [So sánh ACL/JWT/S3](COMPARISON.md): bảng định tính có nguồn tham khảo.

## Chạy từ thư mục gốc repository

Python 3.10+; bản đo đã chạy bằng Python 3.13. Dùng môi trường ảo:

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install -r tests/requirements.txt
python -m pytest tests -q
python tests/attack.py
python tests/bench/benchmark.py --samples 31 --batch 50
```

Test và benchmark tự nạp `backend/macaroon_core` và thư viện pymacaroons
vendored tại `backend/pymacaroons/pymacaroons`; không thay bằng bản PyPI.
Để chạy cả test của Phần 1 (Linux/macOS):

```bash
PYTHONPATH=backend/pymacaroons:backend python -m pytest tests backend/tests -q
```

PowerShell: đặt `$env:PYTHONPATH="backend/pymacaroons;backend"` trước khi chạy
`python -m pytest tests backend/tests -q`. Ca đa tiến trình dùng fork chỉ chạy
trên nền tảng hỗ trợ fork; Windows sẽ skip ca này.

## Cấu trúc và kết quả

| Tệp/thư mục | Mục đích |
|---|---|
| `test_acceptance.py` | 41 ca: quyền, chia sẻ, tampering, hết hạn, thu hồi, sai file |
| `test_pentest.py` | 6 ca xfail ghi nhận 3 lỗi chưa sửa, gồm smoke fuzz 2.000 mutation |
| `attack.py` | Chạy 28 ca tấn công/từ chối, xuất `results/attacks.xml` |
| `bench/benchmark.py` | Đo token 1–50 caveat và AES-256-GCM |
| `results/tokens.csv`, `aes.csv` | Bảng số liệu để vẽ/trích báo cáo |
| `results/samples.json`, `metadata.json` | Mẫu thời gian thô, máy đo, phiên bản và phương pháp |
| `results/*.png` | Ba biểu đồ kích thước token, verify, thông lượng AES |
| `results/*.xml` | Bằng chứng pytest/JUnit; mỗi file là một lần chạy, không cộng dồn số test |

Kết quả tại thời điểm bàn giao: **307 passed, 6 xfailed** khi chạy cả hai
phần; riêng Phần 2 **41 passed, 6 xfailed**. Xfail là kỳ vọng bảo mật đang
thất bại do lỗi đã biết, không phải lỗi đã sửa. Để hiện lỗi gốc:

```bash
python -m pytest tests/test_pentest.py --runxfail -q
```

## Phần còn phải làm

- Phần 1: xử lý mất cập nhật thu hồi giữa nhiều worker, lỗi identifier UTF-8,
  và mất revocation metadata theo `PENTEST_FINDINGS.md`. Sau sửa, bỏ marker
  xfail tương ứng và chạy lại cả suite.
- Phần 3: khi có HTTP/frontend, chạy lại qua API/trình duyệt; kiểm tra headers,
  status/error JSON, fragment, nonce AES-GCM và log. Hiện chỉ kiểm thử service.
- Nhóm viết báo cáo: dùng notes, CSV và 2–3 biểu đồ để tự viết Đánh giá theo
  quy định trong CONTRIBUTING.md. Đây chưa phải bản văn báo cáo nộp.
- Ed25519 là hạng mục tùy chọn chưa triển khai; không có số liệu HMAC/Ed25519.

## Giới hạn số liệu

Ứng dụng chỉ cho tối đa 20 caveat. Điểm 21–50 đo thư viện và xác nhận core từ
chối; không sửa giới hạn ứng dụng để chạy benchmark. Core verify và library
verify có phạm vi khác nhau, đã ghi trong metadata. AES đo Python cryptography,
không phải WebCrypto, HTTP hay I/O. Mỗi điểm có 5 warmup, 31 batch × 50 lần;
báo median của thời gian trung bình mỗi batch. Kết quả trên một máy không là
đảm bảo hiệu năng tổng quát. Các XML/metadata cũ giữ thông tin lúc đo.
