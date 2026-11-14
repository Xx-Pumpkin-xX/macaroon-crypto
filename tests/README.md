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
| `test_pentest.py` | 6 ca cho 3 lỗi F01–F03, gồm smoke fuzz 2.000 mutation; F02, F03 đã sửa nên pass, còn 1 xfail cho F01 |
| `attack.py` | Chạy 28 ca tấn công/từ chối, xuất `results/attacks.xml` |
| `bench/benchmark.py` | Đo token 1–50 caveat và AES-256-GCM |
| `results/tokens.csv`, `aes.csv` | Bảng số liệu để vẽ/trích báo cáo |
| `results/samples.json`, `metadata.json` | Mẫu thời gian thô, máy đo, phiên bản và phương pháp |
| `results/*.png` | Ba biểu đồ kích thước token, verify, thông lượng AES |
| `results/*.xml` | Bằng chứng pytest/JUnit; mỗi file là một lần chạy, không cộng dồn số test |

Kết quả hiện tại (14/11, `main`): **453 passed, 1 xfailed** khi chạy toàn bộ
(`python -m pytest -q`); riêng Phần 2 **46 passed, 1 xfailed**. Xfail còn lại là
F01 (thu hồi giữa nhiều process), lỗi đã biết, tránh bằng cách chạy 1 process.
GitHub Actions chạy lại toàn bộ suite mỗi lần push. Khi bàn giao (9/11) con số là
307 passed, 6 xfailed. Để hiện lỗi gốc của F01:

```bash
python -m pytest tests/test_pentest.py --runxfail -q
```

## Trạng thái các việc còn lại

- F02 (identifier UTF-8) đã sửa ở `a734aad`, F03 (mất metadata thu hồi) đã sửa ở
  `49cf05f`. F01 (nhiều worker) vẫn mở: bản demo chạy 1 process.
- Lớp HTTP và frontend đã có; kịch bản được chạy lại qua trình duyệt ở trang
  Attack lab của bản demo (12/12 đúng thiết kế).
- Ed25519 là hạng mục tùy chọn, nhóm không triển khai.

## Giới hạn số liệu

Ứng dụng chỉ cho tối đa 20 caveat. Điểm 21–50 đo thư viện và xác nhận core từ
chối; không sửa giới hạn ứng dụng để chạy benchmark. Core verify và library
verify có phạm vi khác nhau, đã ghi trong metadata. AES đo Python cryptography,
không phải WebCrypto, HTTP hay I/O. Mỗi điểm có 5 warmup, 31 batch × 50 lần;
báo median của thời gian trung bình mỗi batch. Kết quả trên một máy không là
đảm bảo hiệu năng tổng quát. Các XML/metadata cũ giữ thông tin lúc đo.
