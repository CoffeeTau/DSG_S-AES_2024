import numpy as np
from GF2N import GF2N
from utils import decimalToNpBinary
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import loginSQL
from flask import Flask, request, jsonify, render_template,g
import plotly.express as px
import os
from SAES import SAES,meet_in_the_middle_attack
import numpy as np
import json
from StringSAES import StringSAES
from DoubleSAES import DoubleSAES
from TripleSAES import TripleSAESThreeKeys,TripleSAESTwoKeys
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 添加secret_key以启用flash功能

global a
a = 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user-register.html', methods=['GET'])
def user_register_page():
    return render_template('user-register.html')  # 渲染注册页面

@app.route('/check_user', methods=['GET'])
def check_user():
    username = request.args.get('username', '').strip()
    password = request.args.get('password', '').strip()

    # if not username or not password:
    #     return render_template('index.html', error_message="用户名和密码不能为空")  # 处理空输入
    #
    # # 如果用户名不存在
    # result = loginSQL.search_by_name(username)
    # if not result:
    #     return render_template('index.html', error_message="用户不存在")  # 返回一个错误页面
    #
    #
    # # 验证密码
    # if password == result[2]:
    #     return render_template('system.html')  # 假设这是用户的主页面
    # else:
    #     return render_template('index.html', error_message="密码错误")  # 返回错误信息

    return render_template('system.html')



@app.route('/user-register', methods=['POST'])
def user_register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'message': "用户名和密码不能为空"})  # 处理空输入

    result = loginSQL.search_by_name(username)
    if not result:
        loginSQL.insert_user(username, password)  # 确保密码是安全存储的
        flash('注册成功，请登录！')  # 使用 flash 显示成功提示信息
        return jsonify({'success': True, 'redirect': url_for('index')})  # 注册成功
    else:
        return jsonify({'success': False, 'message': '用户已存在'})  # 用户已存在

# ------------------------------------单次加密 --------------------------
@app.route('/singleEncrypt', methods=['POST'])
def singleEncrypt():

    encoding_type = request.form.get('n1')
    message = request.form.get('plaintext')
    key = request.form.get('key')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key: {key}")
    key = np.array(list(map(int, key)), dtype=np.uint8)
    sdes = SAES(key)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        print
        for arr in groups:
            encrypted = sdes.encrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encryptor = StringSAES(key)

        key = np.array(list(map(int, key)), dtype=np.uint8)
        encrypted_message = encryptor.encryptString(message)

    print(f"Encrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)


# ------------------------------------双重加密 --------------------------
@app.route('/doubleEncrypt', methods=['POST'])
def doubleEncrypt():

    encoding_type = request.form.get('n1')
    message = request.form.get('plaintext')
    key1 = request.form.get('key1')
    key2 = request.form.get('key2')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key1: {key1}, Key2: {key2}")
    key1 = np.array(list(map(int, key1)), dtype=np.uint8)
    key2 = np.array(list(map(int, key2)), dtype=np.uint8)
    sdes = DoubleSAES(key1, key2)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        print
        for arr in groups:
            encrypted = sdes.DoubleBitEncrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encrypted_message = sdes.DoubleStringEncrypt(message)

    print(f"Encrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)



# ------------------------------------三重加密+两个密钥 --------------------------
@app.route('/tripleEncrypt_two', methods=['POST'])
def tripleEncrypt_two():

    encoding_type = request.form.get('n1')
    message = request.form.get('plaintext')
    key1 = request.form.get('key1')
    key2 = request.form.get('key2')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key1: {key1}, Key2: {key2}")
    key1 = np.array(list(map(int, key1)), dtype=np.uint8)
    key2 = np.array(list(map(int, key2)), dtype=np.uint8)
    sdes = TripleSAESTwoKeys(key1, key2)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        print
        for arr in groups:
            encrypted = sdes.BitEncrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encrypted_message = sdes.StringEncrypt(message)

    print(f"Encrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)


# ------------------------------------三重加密+三个密钥 --------------------------
@app.route('/tripleEncrypt_three', methods=['POST'])
def tripleEncrypt_three():

    encoding_type = request.form.get('n1')
    message = request.form.get('plaintext')
    key1 = request.form.get('key1')
    key2 = request.form.get('key2')
    key3 = request.form.get('key3')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key1: {key1}, Key2: {key2}")
    key1 = np.array(list(map(int, key1)), dtype=np.uint8)
    key2 = np.array(list(map(int, key2)), dtype=np.uint8)
    key3 = np.array(list(map(int, key3)), dtype=np.uint8)
    sdes = TripleSAESThreeKeys(key1, key2,key3)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        print
        for arr in groups:
            encrypted = sdes.BitEncrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encrypted_message = sdes.StringEncrypt(message)

    print(f"Encrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)


# ------------------------------------单次解密 --------------------------
@app.route('/singleDecrypt', methods=['POST'])
def singleDecrypt():

    encoding_type = request.form.get('n1')
    message = request.form.get('cyphertext')
    key = request.form.get('key')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key: {key}")
    key = np.array(list(map(int, key)), dtype=np.uint8)
    sdes = SAES(key)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        for arr in groups:
            encrypted = sdes.decrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encryptor = StringSAES(key)
        key = np.array(list(map(int, key)), dtype=np.uint8)
        encrypted_message = encryptor.decryptString(message)

    print(f"Decrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)

# ------------------------------------双重解密 --------------------------
@app.route('/doubleDecrypt', methods=['POST'])
def doubleDecrypt():

    encoding_type = request.form.get('n1')
    message = request.form.get('cyphertext')
    key1 = request.form.get('key1')
    key2 = request.form.get('key2')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key1: {key1}, Key2: {key2}")
    key1 = np.array(list(map(int, key1)), dtype=np.uint8)
    key2 = np.array(list(map(int, key2)), dtype=np.uint8)
    sdes = DoubleSAES(key1, key2)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        for arr in groups:
            encrypted = sdes.DoubleBitDecrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encrypted_message = sdes.DoubleStringDecrypt(message)

    print(f"Encrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)


# ------------------------------------三重解密+两个密钥 --------------------------
@app.route('/tripleDecrypt_two', methods=['POST'])
def tripleDecrypt_two():

    encoding_type = request.form.get('n1')
    message = request.form.get('plaintext')
    key1 = request.form.get('key1')
    key2 = request.form.get('key2')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key1: {key1}, Key2: {key2}")
    key1 = np.array(list(map(int, key1)), dtype=np.uint8)
    key2 = np.array(list(map(int, key2)), dtype=np.uint8)
    sdes = TripleSAESTwoKeys(key1, key2)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        print
        for arr in groups:
            encrypted = sdes.BitDecrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encrypted_message = sdes.StringDecrypt(message)

    print(f"Decrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)


# ------------------------------------三重解密+三个密钥 --------------------------
@app.route('/tripleDecrypt_three', methods=['POST'])
def tripleDecrypt_three():

    encoding_type = request.form.get('n1')
    message = request.form.get('plaintext')
    key1 = request.form.get('key1')
    key2 = request.form.get('key2')
    key3 = request.form.get('key3')

    print(f"Encoding Type: {encoding_type}, Message: {message}, Key1: {key1}, Key2: {key2}")
    key1 = np.array(list(map(int, key1)), dtype=np.uint8)
    key2 = np.array(list(map(int, key2)), dtype=np.uint8)
    key3 = np.array(list(map(int, key3)), dtype=np.uint8)
    sdes = TripleSAESThreeKeys(key1, key2,key3)

    if encoding_type == 'bit':

        message = np.array(list(map(int, message)), dtype=np.uint8)
        
        groups = [message[i:i + 16] for i in range(0, len(message), 16)]
        # 如果最后一组不满16位，用'0'补齐
        if len(groups[-1]) < 16:
            groups[-1] = np.pad(groups[-1], (0, 16 - len(groups[-1])), 'constant')

        encrypted_message = ""
        print
        for arr in groups:
            encrypted = sdes.BitDecrypt(arr)
            encrypted_message_str = ''.join(map(str, encrypted))
            encrypted_message += encrypted_message_str
    else:
        encrypted_message = sdes.StringDecrypt(message)

    print(f"Decrypted Message: {encrypted_message}")
    return jsonify(result=encrypted_message)


# ------------------------------------中间攻击测试 --------------------------
@app.route('/bruteForce', methods=['POST'])
def bruteForce():
    global a

    message_plain = request.form.get('message_plain')
    message_cipher = request.form.get('message_cipher')

    print(f" Message Plain: {message_plain}, Message Cipher: {message_cipher}")  # Debugging line
    
    message_plain = np.array(list(map(int, message_plain)), dtype=np.uint8)
    message_cipher = np.array(list(map(int, message_cipher)), dtype=np.uint8)

    start_time = time.time()  # 记录开始时间

    possible_keys = range(65536)  # 假设密钥是16位长（0-65535）

    # 存储中间结果的字典
    encrypt_dict = {}
    decrypt_dict = {}

    # 遍历所有可能的 K1，对明文进行加密，存储中间结果
    for k1 in possible_keys:
        a = a+1
        k1_bin = np.array([int(bit) for bit in f'{k1:016b}'])
        saes = SAES(key=k1_bin)
        intermediate = saes.encrypt(message_plain)
        intermediate_str = ''.join(map(str, intermediate))  # 将中间结果转换为字符串
        encrypt_dict[intermediate_str] = k1

    # 遍历所有可能的 K2，对密文进行解密，存储中间结果
    for k2 in possible_keys:
        a = a+1
        k2_bin = np.array([int(bit) for bit in f'{k2:016b}'])
        saes = SAES(key=k2_bin)
        intermediate = saes.decrypt(message_cipher)
        intermediate_str = ''.join(map(str, intermediate))  # 将中间结果转换为字符串
        decrypt_dict[intermediate_str] = k2

    # 查找相同的中间结果
    for intermediate_str in encrypt_dict:
        a = a+1
        print(f"中间结果: {intermediate_str}")
        if intermediate_str in decrypt_dict:
            k1 = encrypt_dict[intermediate_str]
            k2 = decrypt_dict[intermediate_str]
            k1 = decimalToNpBinary(k1)
            k2 = decimalToNpBinary(k2)

            print(f"找到密钥对: K1={k1}, K2={k2}")

            end_time = time.time()
            time_use = end_time - start_time

            print("执行中间相遇攻击所需时间:", time_use)

            key1 = ''.join(map(str, k1))
            key2 = ''.join(map(str, k2))
            return jsonify(time=time_use,key1=key1,key2=key2)


# ------------------------------------获取全局变量 --------------------------
@app.route('/get_global_variable')
def get_global_variable():
    global a
    print(f"Global Variable: {a}")  # Debugging line
    return jsonify(global_variable = a)  # 返回全局变量值


# 第一次按破解的时候，清零全局变量
@app.route('/reset_variable')
def reset_variable():
    global a
    a = 0  # 清零全局变量
    print("Global Variable has been reset.")  # 调试输出清零操作
    return jsonify(message="Global variable reset to 0")  # 返回清零状态

# CBC -------------------------------------------------------------------------
@app.route('/cbc_encrypt', methods=['POST'])
def cbc_encrypt():
    # 获取请求中的数据
    data = request.get_json()
    plaintext = data.get("plaintext")  # 明文
    key1 = data.get("key1")  # 密钥
    iv = data.get("iv")  # IV 向量
    output_format = data.get("format")  # 输出格式（bit 或 ASCII）

    # 检查输入是否有效
    if not plaintext or not key1 or not iv:
        return jsonify(error="请输入明文、密钥和IV"), 400

    # 确保密钥和 IV 是 16 字节
    if len(key1) != 16 or len(iv) != 16:
        return jsonify(error="密钥和 IV 必须为16字节 (128位)"), 400

    # 将明文转为字节类型（这里假设明文是 ASCII 格式）
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key1.encode('utf-8')
    iv_bytes = iv.encode('utf-8')

    # 使用 AES CBC 模式进行加密
    try:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()

        # 使用 PKCS7 填充明文到 16 字节的倍数
        pad_len = 16 - len(plaintext_bytes) % 16
        padded_plaintext = plaintext_bytes + bytes([pad_len] * pad_len)

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # 根据用户选择的输出格式决定密文编码
        if output_format == "bit":
            # 转换为二进制 01 串
            ciphertext_output = ''.join(format(byte, '08b') for byte in ciphertext)
        elif output_format == "ASCII":
            # 转换为 Base64 编码
            ciphertext_output = base64.b64encode(ciphertext).decode('utf-8')
        else:
            return jsonify(error="无效的输出格式"), 400
    except Exception as e:
        return jsonify(error=f"加密错误: {str(e)}"), 500

    # 返回加密结果
    return jsonify(result=ciphertext_output)


@app.route('/cbc_decrypt', methods=['POST'])
def cbc_decrypt():
    try:
        # 获取请求中的数据
        data = request.get_json()
        ciphertext = data.get("ciphertext")  # 密文
        key1 = data.get("key1")              # 密钥
        iv = data.get("iv")                  # IV 向量
        output_format = data.get("format")   # 密文格式（bit 或 ASCII）

        # 检查输入是否有效
        if not ciphertext or not key1 or not iv:
            return jsonify(error="请输入密文、密钥和IV"), 400

        # 确保密钥和 IV 是 16 字节
        if len(key1) != 16 or len(iv) != 16:
            return jsonify(error="密钥和 IV 必须为16字节 (128位)"), 400

        # 处理密文格式
        if output_format == "bit":
            # 如果密文是 01 串
            ciphertext_bytes = int(ciphertext, 2).to_bytes((len(ciphertext) + 7) // 8, byteorder='big')
        elif output_format == "ASCII":
            # 如果密文是 Base64 编码
            ciphertext_bytes = base64.b64decode(ciphertext)
        else:
            return jsonify(error="无效的密文格式"), 400

        # 转换密钥和 IV 为字节类型
        key_bytes = key1.encode('utf-8')
        iv_bytes = iv.encode('utf-8')

        # 使用 AES CBC 模式进行解密
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()

        # 移除 PKCS7 填充
        pad_len = padded_plaintext[-1]
        plaintext_bytes = padded_plaintext[:-pad_len]

        # 将明文转换为字符串
        plaintext = plaintext_bytes.decode('utf-8')
        return jsonify(result=plaintext)

    except Exception as e:
        print("解密时发生错误:", str(e))  # 在控制台中输出详细错误信息
        return jsonify(error=f"解密错误: {str(e)}"), 500



if __name__ == '__main__':
    app.run(debug=True)
