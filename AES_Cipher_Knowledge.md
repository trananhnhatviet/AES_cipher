# AES Cipher Knowledge

-   AES là viết tắt của Advanced Encryption Standard (tiêu chuẩn mã hóa nâng cao), bằng cách sử dụng cùng một khóa để mã hóa và giải mã dữ liệu. Thuật toán này được xây dựng trên các phép toán logic và số học như thay thế, hoán vị và cộng trên các khối dữ liệu có kích thước cố định.
-   AES được đặc trưng bởi kích thước khóa, có thể là 128-bit, 192-bit hoặc 256-bit. Trong quá trình mã hóa, dữ liệu được chia thành các khối có kích thước 128-bit và sau đó được xử lý thông qua các vòng lặp liên tiếp, mỗi vòng lặp bao gồm các phép toán khác nhau như thay thế, hoán vị, trộn và thay đổi khóa. Mỗi khối dữ liệu sẽ được mã hóa bằng cùng một khóa và phép toán này được thực hiện đối với từng khối cho đến khi toàn bộ dữ liệu được mã hóa.


-   Trước hết, bạn nên xem video này để tìm hiểu qua về AES cipher [click here](https://www.youtube.com/watch?v=gP4PqVGudtg)

-   **Cơ chế mã hóa của AES sẽ như sau:**
    -   Trước hết, AES sẽ chia plaintext (thường là 128 bits (16 bytes)) thành 4 phần, mỗi phần rồi xếp thành 1 ma trận 4x4, mỗi cột là 4 bytes như sau:
    ![](https://i.imgur.com/ZHszJXS.png)

    -   Gồm 4 round để mã hóa:
        -   Sub Bytes
        -   Shift Rows
        -   Mix Colums
        -   Add Round Key
    -   Round cuối sẽ không có Mix Colums

        ![](https://i.imgur.com/zC1OdSX.png)

        -   Round cuối cùng không có bước MixColumn

        -   Bước SubBytes dùng để thay thế (substitution), bước ShiftRows và MixColumn dùng để hoán vị thuật toán (permutation) trong thuật toán.

**Add Round Key**
___

-   Khi ta có 1 Round Key, ta xor từng phần tử của state (trạng thái hiện tại) với Round Key.

    ![](https://i.imgur.com/cvm9jIJ.png)

-   Đoạn code để xor từng phần tử của state với Round Key

```
def add_round_key(state, key):
    """
    Perform the AddRoundKey operation of AES by XORing each byte of the state
    with the corresponding byte of the key.
    """
    assert len(state) == len(key), "State and key sizes do not match"
    return bytes([s ^ k for s, k in zip(state, key)])
```

**Sub Bytes**
___
-   Sub Bytes là bước mà thay thế 1 bytes trong Plaintext_Block thành 1 bytes khác trong bảng S-box (bảng thay thế)
![](https://i.imgur.com/BFYyjIA.png)


-   Ví dụ như sau:
```
#Ma trận cần Sub Bytes
state = [
[251, 64, 182, 81],
[146, 168, 33, 80],
[199, 159, 195, 24],
[64, 80, 182, 255],
]

#Ma trận Sbox (lúc chạy thì xóa các tung và hoành độ đi, mình để thế cho dễ nhìn lúc đọc thui nhaaa)
s_box = (
   |  0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
---| -- | ---  | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
00 |0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
10 |0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
20 |0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
30 |0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
40 |0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
50 |0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
60 |0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
70 |0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
80 |0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
90 |0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
a0 |0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
b0 |0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
c0 |0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
d0 |0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
e0 |0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
f0 |0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)#Cách Sub Bytes
def sub_bytes(s,s_box):
    
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]
    return s#Output:
[[99, 114, 121, 112],
[116, 111, 123, 108],
[49, 110, 51, 52],
[114, 108, 121, 125]]
```

-   Với số đầu tiên là 251, Hexa là fb, sau khi Sub Bytes, 251 --> 99 ví s_box(f,b) = 63 (sang decimal là 99), tương tự với các phần tử khác của ma trận state

**Shift Rows**
___
-   Shift Rows là bước để dịch chuyển những hàng của ma trận, hàng đầu tiên sẽ dịch chuyển 0 bytes(có thể nói là không dịch chuyển), hàng thứ 2 sẽ dịch chuyển 1 bytes, hàng thứ 3 sẽ dịch chuyển 2 bytes, hàng thứ 4 sẽ dịch chuyển 3 bytes
-   Nếu bạn không hiểu thì có thể tham khảo hình sau:
![](https://i.imgur.com/iFKOHpA.png)
-   Ví dụ như sau:
    
```
#Hàm Shift_row ma trận
def shift_rows(s):
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]
    return s

#input
state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
    ]

shift_rows_state = shift_rows(state)
for i in range(4):
    print(shift_rows_state[i])

#Output
    [251, 64, 182, 81]
    [168, 33, 80, 146]
    [195, 24, 199, 159]
    [255, 64, 80, 182]
```

**Mix Columns**
___
-   Bước này, ta cần nhân từng cột của ma trận cần mã hóa với 1 ma trận cụ thể để ra 1 ma trận mới do các bytes trong cột bị thay đổi
-   Ví dụ, ta có 1 ma trận mẫu
![](https://i.imgur.com/E5Wsmy9.png)
-   Sau đó, ma trận trạng thái sẽ được xử lý như sau
![](https://i.imgur.com/SQIsHZW.png)
-   Lấy 1 ví dụ khác và code bằng Python

```
def mix_columns(state, form):
    for i in range(4):
        a = state[i][0]
        b = state[i][1]
        c = state[i][2]
        d = state[i][3]

        state[i][0] = (form[0][0] * a + form[0][1] * b + form[0][2] * c + form[0][3] * d) % 256
        state[i][1] = (form[1][0] * a + form[1][1] * b + form[1][2] * c + form[1][3] * d) % 256
        state[i][2] = (form[2][0] * a + form[2][1] * b + form[2][2] * c + form[2][3] * d) % 256
        state[i][3] = (form[3][0] * a + form[3][1] * b + form[3][2] * c + form[3][3] * d) % 256

    return state


state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
    ]
form = [
    [1,2,3,4],
    [5,6,7,8],
    [9,10,11,12],
    [13,14,15,16],
]

x=(mix_columns(state,form))
for i in x:
    print(i)

#Output
#[225, 233, 241, 249]
#[133, 49, 221, 137]
#[174, 178, 182, 186]
#[254, 18, 38, 58]

```

**AES Key schedule**
___

-   Nếu như gặp bài có tổng cộng 10 round thì ta phải kiếm 11 cái subkey đúng khum nà, nhưng mà tự nhập bằng tay có mà chớt mấc, nên là phương pháp này sẽ cung cấp 10 round key và chỉ cần nhập 1 key ban đầu
-   Bắt đầu với 1 khóa bí mật ``de6916a49c65d8d260ea5da05cf257ea`` thành 4 cột:
```
#w0 w1 w2 w3
 de 69 16 a4 
 9c 65 d8 d2 
 60 ea 5d a0 
 5c f2 57 ea 
```
-   Mục tiêu là tìm được w4, w5, w6, w7 là khóa con thứ 1
-   Sau đó, ta thực hiện RotWord với cột thứ 4
```
#Cái này tự code đi nhaaa, giống Shift_rows á :v
d2
a0
ea
a4
```
-   Tiếp theo, ta sử dụng thao tác SubWord, mỗi byte được thay thế bằng cách sử dụng hộp S mà chúng ta đã xem xét trong bước SubBytes. Giả sử sau khi SubWord, ta thu được cột như sau:
```
#Này cũng tự code nha
x0
x1
x2
x3
```
-   Cuối cùng, trong thao tác Rcon (hằng số vòng), cột được thêm vào một cột không đổi được xác định trước tương ứng với vòng hiện tại. Việc bổ sung ở đây tất nhiên là hoạt động xor. Đối với khóa 128 bit, các vectơ cột không đổi này là:
![](https://i.imgur.com/301FAWk.png)

-   Có nghĩa là ta sẽ làm như sau:
```
#Đang ở round 1 nên ta sẽ dùng 01 00 00 00
y0 = x0 ⊕ 01
y1 = x1 ⊕ 00
y2 = x2 ⊕ 00
y3 = x3 ⊕ 00
```
-   Và các giá trị y kia gọi đặt tên là W_processed, các w4, w5, w6, w7 tiếp theo sẽ làm như sau:
```
w4 = w0 ⊕ W_processed
w5 = w1 ⊕ w4
w6 = w2 ⊕ w5
w7 = w3 ⊕ w6
``` 
-   Đó chính là round 1, với các round tiếp theo thì vẫn làm như thế nhưng mà sẽ đổi cột Rcon
-   Đoạn function tính rcon thứ i
```
def Rcon(i):
    """
    Calculate the value of the Rcon constant at position i.
    """
    Rcon_value = 1
    if i == 0:
        return 0
    
    # If i is not zero, use a loop to calculate the Rcon value
    for j in range(1, i):
        # Perform a left circular shift on Rcon_value
        Rcon_value = ((Rcon_value << 1) % 0x100) 
        
        # Check if the leftmost bit of Rcon_value is set
        if Rcon_value & 0x80 == 0x80:
            # If so, perform a bitwise XOR with the value 0x1b
            Rcon_value = (Rcon_value ^ 0x1b) % 0x100
            
    return Rcon_value

```

**Tóm tắt thuật toán**
-   Trước hết, quá trình mở rộng khóa diễn ra, sử dụng khóa bí mật 128 bit do người dùng cung cấp. Sau đó, đối với bất kỳ khối dữ liệu văn bản gốc 128 bit đã cho nào, phép biến đổi sau đây được áp dụng:

-   Addition of the first round key
    9 Rounds:
    -   Substitute Bytes
    -   Shift Rows
    -   Mix Columns
    -   Adding the Round Key
-   The final round
    -   Substitute Bytes
    -   Shift Rows
    -   Adding the Round Key
