import re

import numpy as np
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES

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
# 实现一个简单的16-bit CBC模式加密函数
def xor(bits1, bits2):
    """对两个二进制字符串进行按位异或操作"""
    return ''.join(['0' if bits1[i] == bits2[i] else '1' for i in range(len(bits1))])


def saes_encrypt(plaintext, key):
    """一个简单的SAES加密函数（占位）"""
    return ''.join(reversed(plaintext))


def saes_decrypt(ciphertext, key):
    """一个简单的SAES解密函数（占位）"""
    return ''.join(reversed(ciphertext))


def cbc_encrypt(plaintext, key, iv):
    block_size = 16

    key_array = np.array([int(bit) for bit in key])
    saes = SAES(key_array)

    if len(plaintext) % block_size != 0:
        padding_length = block_size - (len(plaintext) % block_size)
        plaintext = plaintext + '0' * padding_length

    ciphertext = ""
    prev_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        block = xor(block, prev_block)

        # 在使用 saes.encrypt 前将 block 转换为 NumPy 数组
        block_np = np.array([int(bit) for bit in block])  # 转换为01的NumPy数组
        encrypted_block = saes.encrypt(block_np)
        encrypted_block = ''.join(map(str, encrypted_block))

        # encrypted_block = saes_encrypt(block, key)

        ciphertext += encrypted_block
        prev_block = encrypted_block

    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    """实现CBC模式解密"""
    block_size = 16
    key_array = np.array([int(bit) for bit in key])
    saes = SAES(key_array)
    plaintext = ""
    prev_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]

        block_np = np.array([int(bit) for bit in block])
        decrypted_block = saes.decrypt(block_np)
        decrypted_block = ''.join(map(str, decrypted_block))

        # decrypted_block = saes_decrypt(block, key)

        plaintext_block = xor(decrypted_block, prev_block)
        plaintext += plaintext_block
        prev_block = block  # 更新前一个密文块

    return plaintext.rstrip('0')  # 移除填充的0


@app.route('/cbc_encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form.get('plaintext')
    key = request.form.get('key1')
    iv = request.form.get('ivInput')

    if not re.match(r'^[01]+$', plaintext):
        return jsonify({'error': '明文应为二进制格式（仅包含0和1）'}), 400
    if not re.match(r'^[01]{16}$', key):
        return jsonify({'error': '密钥应为16位二进制格式'}), 400
    if not re.match(r'^[01]{16}$', iv):
        return jsonify({'error': 'IV应为16位二进制格式'}), 400

    ciphertext = cbc_encrypt(plaintext, key, iv)
    return jsonify({'ciphertext': ciphertext})


@app.route('/cbc_decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext')
    key = request.form.get('key1')
    iv = request.form.get('ivInput')

    if not re.match(r'^[01]+$', ciphertext):
        return jsonify({'error': '密文应为二进制格式（仅包含0和1）'}), 400
    if not re.match(r'^[01]{16}$', key):
        return jsonify({'error': '密钥应为16位二进制格式'}), 400
    if not re.match(r'^[01]{16}$', iv):
        return jsonify({'error': 'IV应为16位二进制格式'}), 400

    plaintext = cbc_decrypt(ciphertext, key, iv)
    return jsonify({'plaintext': plaintext})







if __name__ == '__main__':
    app.run(debug=True)
