# Bai-tap
# Bài 1.1 - Minh họa bố trí bộ nhớ trong C++

## Giới thiệu
Chương trình minh họa cách các biến được lưu trữ trong bộ nhớ của chương trình C++.

Các vùng nhớ được sử dụng:
- Global Memory
- Stack Memory
- Static Memory
- Heap Memory

Chương trình sẽ:
- Khởi tạo biến ở từng vùng nhớ.
- In địa chỉ của từng biến.
- Chuyển địa chỉ sang kiểu `uintptr_t`.
- Tính khoảng cách địa chỉ giữa các vùng nhớ.

---

## Kiến thức sử dụng

- Global Variable
- Local Variable
- Static Variable
- New/Delete
- Pointer
- `uintptr_t`
- `reinterpret_cast`

---

## Cấu trúc chương trình

```
bai1.1.cpp
```

### Biến Global

```cpp
int GlobalVar = 10;
```

Lưu trong vùng Global/Data.

### Biến Local

```cpp
int LocalVar = 20;
```

Lưu trong Stack.

### Biến Static

```cpp
static int StaticVar = 30;
```

Lưu trong vùng Static/Data.

### Biến Heap

```cpp
int *p = new int(40);
```

Được cấp phát trên Heap.

---

## Cách hoạt động

1. Tạo biến ở các vùng nhớ khác nhau.
2. In địa chỉ của từng biến.
3. Ép địa chỉ sang kiểu số nguyên (`uintptr_t`).
4. Tính khoảng cách giữa các địa chỉ.
5. Kết thúc chương trình.
6. 
## Ví dụ kết quả

```
Địa chỉ của GlobalVar: 0x55b3...
Địa chỉ của LocalVar: 0x7ffe...
Địa chỉ của StaticVar: 0x55b3...
Địa chỉ của Heap: 0x55b3...

Khoảng cách địa chỉ từ GlobalVar <-> Local: ...
Khoảng cách địa chỉ từ StaticVar <-> Heap: ...
```

Địa chỉ sẽ thay đổi sau mỗi lần chạy do ASLR (Address Space Layout Randomization).

---

## Giải thích

### Global Memory
- Tồn tại trong suốt thời gian chạy chương trình.
- Chứa biến toàn cục.

### Stack
- Chứa biến cục bộ.
- Tự động cấp phát và giải phóng.

### Static Memory
- Chứa biến static.
- Chỉ khởi tạo một lần.

### Heap
- Cấp phát động bằng `new`.
- Phải giải phóng bằng `delete`.

---

## Kiến thức rút ra

- Phân biệt các vùng nhớ trong C++.
- Hiểu cách lấy địa chỉ bằng toán tử `&`.
- Sử dụng con trỏ để quản lý bộ nhớ động.
- Hiểu ý nghĩa của `uintptr_t` khi thao tác với địa chỉ.

---

## Tác giả

Nguyễn Hiệp
