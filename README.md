# Hệ Thống Chấm Điểm, Tổng Hợp & Công Bố Kết Quả FLL Cấp Trường
**Đơn vị tổ chức:** Trường THCS & THPT Đinh Thiện Lý (Lawrence S. Ting School – LSTS)  
**Cuộc thi:** Vòng 3 Tuyển chọn Đội FLL Cấp Trường – Mùa giải BIOGLOW

---

## 1. Cấu trúc Hệ thống & Tính năng Chính

1. **Trang 1 – Trang Giới Thiệu Công Khai (Dành cho Học sinh & Khán giả):**
   - Giới thiệu mùa giải **BIOGLOW**, quy trình thi đấu **Robot Game (110 điểm)** (2 lượt chạy, tối đa 4 phút, lấy điểm cao nhất theo trạng thái cuối cùng, khiếu nại trong 3 phút).
   - Yêu cầu trình bày **Phần 1: Thiết Kế Robot – Robot Design (40 điểm, 2 phút)** (Cấu trúc robot, cảm biến sử dụng, cơ chế thực hiện nhiệm vụ, chương trình điều khiển).
   - Yêu cầu trình bày **Phần 2: Dự Án Đổi Mới – Innovation Project (40 điểm, 2 phút)** (6 định hướng chủ đề Đa dạng sinh học & 4 câu hỏi cốt lõi).
   - Nhấn mạnh cách tính **Điểm Giá Trị Cốt Lõi – Core Values (40 điểm)** trích xuất tự động từ 10 tiêu chí `⚙♥ CV` trên 2 phiếu chấm thuyết trình (`1.2, 2.1, 4.2, 5.1, 5.2` của Thiết Kế Robot + `1.2, 2.2, 3.1, 5.1, 5.2` của Dự Án Đổi Mới).
   - **Cổng Công Bố Kết Quả:** Nút **"XEM KẾT QUẢ CHÍNH THỨC"** bị khóa đối với người dùng bình thường cho đến khi tất cả 8 nhóm (Nhóm 1 đến Nhóm 8) được cập nhật đầy đủ điểm số ở mọi hạng mục.

2. **Hệ thống Đăng nhập & Phân quyền Bảo mật:**
   - **Bắt buộc đăng nhập:** Người dùng bắt buộc phải nhập đúng tên tài khoản và mật khẩu được Ban Tổ Chức cấp riêng mới có thể truy cập màn hình chấm điểm.
   - **Mã hóa toàn diện bằng SHA-256 + Salt:** Toàn bộ tên định danh tài khoản và mật khẩu đều được băm một chiều bằng thuật toán **SHA-256 + Salt** (không lưu tên tài khoản hay mật khẩu dạng văn bản thuần trong mã nguồn hoặc tài liệu công khai).
   - **Phân quyền độc lập theo hạng mục:**
     - **Giám khảo Robot Game (Phòng A211):** Truy cập màn hình **Nhập điểm Robot Game (`[BM01-RG]`)**.
     - **Giám khảo Thuyết trình (Phòng B217):** Truy cập màn hình **Chấm Thiết Kế Robot (`[BM04-RD]`) & Dự Án Đổi Mới (`[BM05-IP]`)**.
     - **Giới hạn quyền xóa của Giám khảo:** Giám khảo chỉ được phép xóa/làm lại điểm của **riêng nhóm mà mình phụ trách chấm** (các nhóm khác và phần chấm của giám khảo khác được bảo vệ an toàn).
   - **Quản trị viên Hệ thống (Ban Tổ Chức):**
     - Có toàn quyền truy cập và quản lý cả 2 phần thi, đồng bộ File Excel trực tuyến bảo mật và **kiểm soát việc cho phép In & Công bố kết quả chính thức**.
   - **Chống xem mã nguồn (View Code Protection):** Khóa thao tác chuột phải (`contextmenu`) và các phím tắt mở công cụ lập trình / xem mã nguồn (`F12`, `Ctrl+U`, `Ctrl+Shift+I/J/C/K`, `Ctrl+S`).

3. **Trang Công Bố Kết Quả & Xét Chọn Top 4 Nhóm (Xử lý Đồng điểm tự động):**
   - Hiển thị vinh danh **04 Nhóm có tổng điểm cao nhất** (trên 230đ) được lựa chọn và bảng xếp hạng toàn diện cả 8 nhóm.
   - **Thuật toán phân định khi đồng điểm (Tie-breaker Rules):**
     1. **Điểm Robot Game cao hơn** (Tối đa 110đ)
     2. **Điểm Thiết Kế Robot (Robot Design) cao hơn** (Tối đa 40đ)
     3. **Điểm Giá Trị Cốt Lõi (Core Values) cao hơn** (Tối đa 40đ)
     4. **Thời gian hoàn thành Robot Game nhanh hơn** (Tính theo giây)

---

## 2. Hướng dẫn Đưa lên GitHub Pages

1. Tạo một Repository mới trên GitHub (ví dụ: `fll-lsts-bioglow`).
2. Tải 3 file trong thư mục `fll-lsts-bioglow-web` lên nhánh `main` của Repository:
   - `index.html`
   - `styles.css`
   - `app.js`
3. Vào mục **Settings** $\rightarrow$ **Pages** của Repository trên GitHub.
4. Tại mục **Build and deployment** $\rightarrow$ **Branch**, chọn nhánh `main` (thư mục `/ (root)`) và bấm **Save**.
5. Sau khoảng 30–60 giây, website sẽ hoạt động tại địa chỉ `https://<ten-tai-khoan>.github.io/fll-lsts-bioglow/`.
