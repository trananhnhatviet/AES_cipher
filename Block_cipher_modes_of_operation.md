# Block cipher modes of operation
**1.  Electronic Code Book (ECB)**
___
-   Electronic Code Book (ECB) là một trong những chế độ hoạt động của AES (Advanced Encryption Standard) - một thuật toán mã hóa đối xứng tiêu chuẩn được sử dụng rộng rãi trong các ứng dụng bảo mật.
-    Trong chế độ ECB, dữ liệu được chia thành các khối có kích thước cố định và mỗi khối được mã hóa độc lập với các khối khác bằng cách sử dụng cùng một khóa mã hóa.
![](https://i.imgur.com/Fmy4D2q.png)
-   Trong quá trình mã hóa, mỗi khối dữ liệu được truyền qua hàm mã hóa để tạo ra một chuỗi mã hóa tương ứng. Điều này có nghĩa là các khối dữ liệu giống nhau sẽ được mã hóa thành một chuỗi mã hóa giống nhau. Khi khối dữ liệu mã hóa được kết hợp lại, ta sẽ có được chuỗi mã hóa hoàn chỉnh.
-   Tuy nhiên, ECB có nhược điểm là không đảm bảo tính bảo mật cao nếu các khối mã hóa có cùng nội dung. Các kẻ tấn công có thể dễ dàng phát hiện ra sự trùng lặp giữa các khối dữ liệu và dễ dàng tấn công bằng các phương pháp tấn công theo phương pháp "chosen-plaintext" hoặc "ciphertext-only". Do đó, ECB không được sử dụng rộng rãi trong các ứng dụng bảo mật.
-   Đoạn code minh họa về cách mã hóa và giải mã ECB:
```
import base64 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from binascii  import*

data = 'Tran Anh Nhat Viet dep trai' # Đây là dữ liệu cần mã hóa
key = b'1122334455667788'            # Đây là key (phải là 16 ký tự nếu là AES 128) 


def encrypt(raw): 
    raw = pad(raw.encode(),16) # Thêm các byte không có giá trị để đảm bảo độ dài là bội số của 16 
    print('raw after pad:', raw)   
    cipher = AES.new(key, AES.MODE_ECB)    
    return (cipher.encrypt(raw)).hex()

def decrypt(enc):
    enc = unhexlify(enc)
    cipher = AES.new(key, AES.MODE_ECB)
    print('cipher:', cipher.decrypt(enc))
    return unpad(cipher.decrypt(enc),16) # Bỏ bớt các byte không có giá trị

encrypted = encrypt(data)
print('encrypted ECB Hexa:',encrypted)

decrypted = decrypt(encrypted)
print('data: ',decrypted)
```


**2. Cipher block chaining (CBC)**
___
-   CBC (Cipher Block Chaining) là một trong những chế độ mã hóa trong thuật toán AES (Advanced Encryption Standard). Chế độ CBC được sử dụng để tăng tính an toàn của dữ liệu so với chế độ ECB.
-   CBC hoạt động bằng cách chia các khối plaintext thành các khối có cùng độ dài, sau đó thực hiện mã hóa các khối này bằng thuật toán AES. Tuy nhiên, trước khi mã hóa, mỗi khối plaintext sẽ được XOR với khối ciphertext của khối trước đó. Điều này có nghĩa là, đầu ra của khối trước đó sẽ được dùng để làm "vector khởi đầu" cho khối tiếp theo trước khi thực hiện mã hóa.
![](https://i.imgur.com/ZriVxxG.png)
-   Để bắt đầu quá trình mã hóa, một vector khởi đầu (initialization vector hay IV) được sử dụng cho khối đầu tiên của plaintext. IV có thể được coi như là một khối ciphertext "giả", được tạo ra một cách ngẫu nhiên và được cung cấp cùng với ciphertext đến bên giải mã.
-   Cụ thể, quá trình mã hóa trong chế độ CBC diễn ra như sau:

    -   Khối dữ liệu đầu tiên của plaintext được XOR với IV (Initialization Vector) để tạo khối dữ liệu được mã hóa đầu tiên.
    -   Khối dữ liệu đầu tiên được mã hóa bằng thuật toán AES.
    -   Khối dữ liệu đầu tiên được mã hóa sau đó được XOR với khối dữ liệu tiếp theo của plaintext để tạo khối dữ liệu được mã hóa thứ hai.
    -   Quá trình mã hóa tiếp tục cho đến khi hết các khối dữ liệu của plaintext.
-   Khi giải mã, quá trình giải mã được thực hiện bằng cách giải mã khối ciphertext và sau đó XOR với khối ciphertext của khối trước đó để khôi phục lại khối plaintext gốc. Đối với khối đầu tiên, khối ciphertext của nó sẽ được giải mã bằng thuật toán AES và sau đó XOR với IV để khôi phục lại khối plaintext gốc.
-   Đoạn code minh họa về cách mã hóa và giải mã CBC:
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = b'this_is_a_keycbc'# Đây là key (phải là 16 ký tự nếu là AES 128) 


iv = b'1234567812345678'#Đây là Initialization Vector (phải là 16 ký tự nếu là AES 128) 

# Chuỗi cần được mã hóa
plaintext = b'This is a secret message'

def encrypt_CBC(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv) # Khởi tạo 1 đối tượng AES với key và iv
    plaintext = pad(plaintext,16)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt_CBC(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv) # Khởi tạo 1 đối tượng AES với key và iv
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    return plaintext

# Mã hóa
ciphertext = encrypt_CBC(key, iv, plaintext)
print('Ciphertext:', ciphertext)

# Giải mã
decrypted_text = decrypt_CBC(key, iv, ciphertext)
print('Plaintext:', decrypted_text)
```

**3. Propagating cipher block chaining (PCBC)**
___

-   Propagating cipher block chaining (PCBC) là một phương pháp mã hóa dữ liệu, trong đó, mỗi khối được mã hóa bằng cách kết hợp với khối trước đó thông qua phép XOR trước khi được truyền qua thuật toán mã hóa. Sau đó, khối mã hóa được sử dụng để mã hóa khối tiếp theo. Quá trình này được tiếp tục cho đến khi tất cả các khối dữ liệu được mã hóa.
    ![](https://i.imgur.com/VjRITwM.png)
    ![](https://i.imgur.com/VtrYJj0.png)

-   Quá trình mã hóa bằng PCBC như sau:
    -   Tạo khóa và khối khởi đầu (IV) cho thuật toán mã hóa.
    -   Chia văn bản cần mã hóa thành các khối có cùng độ dài với khối đầu vào của thuật toán mã hóa.
    -   Thực hiện phép XOR giữa khối đầu vào và khối IV để tạo khối mã hóa đầu tiên.
    -   Thực hiện phép XOR giữa khối mã hóa đầu tiên và khối văn bản rõ đầu tiên để tạo khối mã hóa thứ hai.
    -   Tiếp tục thực hiện phép XOR giữa khối mã hóa trước đó và khối văn bản rõ mới để tạo ra khối mã hóa tiếp theo.
    -   Lặp lại quá trình trên cho tất cả các khối văn bản rõ.
    -   Kết quả cuối cùng là chuỗi các khối mã hóa.
-   Quá trình giải mã bằng PCBC như sau:
    -   Tạo khóa và khối khởi đầu (IV) cho thuật toán mã hóa.
    -   Chia chuỗi các khối mã hóa thành các khối có cùng độ dài với khối đầu vào của thuật toán mã hóa.
    -   Thực hiện phép XOR giữa khối đầu vào và khối IV để tạo ra khối văn bản rõ đầu tiên.
    -   Thực hiện phép XOR giữa khối mã hóa đầu tiên và khối văn bản rõ đầu tiên để tạo ra khối văn bản rõ thứ hai.
    -   Tiếp tục thực hiện phép XOR giữa khối mã hóa trước đó và khối văn bản mã hóa để tạo ra khối văn bản rõ tiếp theo.
    -   Lặp lại quá trình trên cho tất cả các khối mã hóa.
    -   Kết quả cuối cùng là chuỗi các khối văn bản rõ.
-   Hiện tại, thuật toán AES không hỗ trợ chế độ hoạt động PCBC nên mục này sẽ không có code nha :v

**4. Cipher Feedback (CFB)**
___
-   Cipher Feedback (CFB) là một mode của thuật toán mã hóa block (block cipher) trong mật mã học. CFB hoạt động bằng cách sử dụng output của block cipher như một số liệu vào cho việc mã hóa dữ liệu tiếp theo, thay vì sử dụng trực tiếp khóa để mã hóa dữ liệu đó.
-   Trong chế độ CFB, các khối plaintext sẽ được chia nhỏ thành các khối con và mỗi khối con này sẽ được mã hóa riêng bằng block cipher. Để thực hiện mã hóa, CFB sử dụng một vector khởi tạo (initialization vector - IV) để bắt đầu quá trình mã hóa. Kết quả của quá trình mã hóa sẽ được XOR với khối plaintext để tạo ra khối ciphertext tương ứng. Sau đó, khối ciphertext này sẽ được sử dụng làm đầu vào cho việc mã hóa khối tiếp theo.
    ![](https://i.imgur.com/YknN5Ik.png)
-   Cụ thể quá trình mã hóa CFB như sau:
    -   Tạo một vector khởi tạo (IV) ngẫu nhiên có độ dài bằng với kích thước của block cipher.
    -   Chia các khối plaintext thành các khối con có độ dài bằng với kích thước của block cipher.
    -   Mã hóa vector khởi tạo bằng block cipher để tạo ra một khối ciphertext.
    -   XOR khối ciphertext này với khối plaintext đầu tiên để tạo ra khối ciphertext đầu tiên.
    -   Sử dụng khối ciphertext đầu tiên để mã hóa khối plaintext thứ hai.
    -   Lặp lại 2 bước cuối

-   Đoạn code minh họa về cách mã hóa và giải mã CFB:
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'1111111111111111'
iv = b'1234567812345678'

def encrypt(plaintext):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(ciphertext):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Mã hóa plaintext
plaintext = b'This is a secret message'
ciphertext = encrypt(plaintext)
print('Ciphertext:', ciphertext.hex())

# Giải mã ciphertext
decrypted_plaintext = decrypt(ciphertext)
print('Decrypted plaintext:', decrypted_plaintext)

```

**5. Output feedback (OFB)**
___
-   Chế độ Output Feedback (OFB) trong mật mã học là một phương pháp sử dụng block cipher để mã hóa dữ liệu theo các khối có kích thước cố định. Giống như Cipher Feedback (CFB), OFB sử dụng một vector khởi tạo (IV) để khởi đầu quá trình mã hóa và sử dụng output của block cipher như một số liệu vào cho việc mã hóa các khối dữ liệu tiếp theo.

-   Trong chế độ CFB, các khối plaintext sẽ được chia nhỏ thành các khối con và mỗi khối con này sẽ được mã hóa riêng bằng block cipher. Để thực hiện mã hóa, OFB sử dụng một vector khởi tạo (initialization vector - IV) để bắt đầu quá trình mã hóa. Kết quả của quá trình mã hóa sẽ được XOR với khối plaintext để tạo ra khối ciphertext tương ứng. Sau đó, khối ciphertext này sẽ được sử dụng làm đầu vào cho việc mã hóa khối tiếp theo.
    ![](https://i.imgur.com/IVaYnPJ.png)
-   Quá trình mã hóa CFB như sau:
    -   Tạo một vector khởi tạo (IV) ngẫu nhiên có độ dài bằng với kích thước của block cipher.
    -   Chia các khối plaintext thành các khối con có độ dài bằng với kích thước của block cipher.
    -   Mã hóa vector khởi tạo bằng block cipher để tạo ra một khối output.
    -   Sử dụng khối output để mã hóa khối plaintext đầu tiên.
    -   Lặp lại 2 bước cuối với các plaintext còn lại.
-   Đoạn code minh họa về cách mã hóa và giải mã OFB:
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'1111111111111111'
iv = b'1234567812345678'

def encrypt(plaintext):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(ciphertext):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Mã hóa plaintext
plaintext = b'This is a secret message'
ciphertext = encrypt(plaintext)
print('Ciphertext:', ciphertext.hex())

# Giải mã ciphertext
decrypted_plaintext = decrypt(ciphertext)
print('Decrypted plaintext:', decrypted_plaintext)

```

**6. Counter (CTR)**
___
-   Chế độ Counter (CTR) trong mật mã học là một phương pháp sử dụng block cipher để mã hóa dữ liệu theo các khối có kích thước cố định, tương tự như Cipher Block Chaining (CBC) và Cipher Feedback (CFB). Tuy nhiên, CTR sử dụng một chuỗi giá trị đếm (counter) để tạo ra các key stream (khối mã hóa) để mã hóa các khối dữ liệu, thay vì sử dụng kết quả của các khối dữ liệu trước đó như CFB hoặc CBC.
    ![](https://i.imgur.com/DN01HSS.png)
-   Quá trình mã hóa CTR như sau:
    -   Tạo một chuỗi giá trị đếm ngẫu nhiên có độ dài bằng với kích thước của block cipher.
    -   Chia các khối plaintext thành các khối con có độ dài bằng với kích thước của block cipher.
    -   Mã hóa chuỗi giá trị đếm bằng block cipher để tạo ra một khối key stream.
    -   XOR khối key stream với khối plaintext để tạo ra khối ciphertext.
    -   Tăng giá trị đếm lên 1 và lặp lại 2 với tất cả các khối plaintext còn lại.


-   Đoạn code minh họa quá trình mã hóa và giải mã của CTR
```
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad,unpad
import binascii

plaintext = b'This is a secret message.'
key = b'1111111111111111'
iv = b'1234567812345678'

def encrypt(plaintext):
    data_bytes = bytes(plaintext)
    cipher = AES.new(key,AES.MODE_CTR)
    ciphertext = cipher.encrypt(data_bytes)
    return ciphertext, cipher.nonce

ciphertext,nonce = encrypt(plaintext)

print(ciphertext)

print(binascii.hexlify(ciphertext))

def decrypt(ciphertext,nonce):
    cipher= AES.new(key,AES.MODE_CTR,nonce=nonce)
    raw_bytes = cipher.decrypt(ciphertext)
    return raw_bytes

plaintext = decrypt(ciphertext,nonce)
print(plaintext)
```