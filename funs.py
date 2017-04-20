# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
import sqlite3
import hashlib
import sys

iv = b'0123456789abcdef'

current_path = sys.path[0]
database_path = current_path + '/pwm.db'


def add_user(password):
    """
    添加用户
    :param password: 密码
    :return: 
    """
    password = __get_md5(password)
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO PWM_USER (PASSWORD) VALUES (?)', (password,))
    cursor.close()
    conn.commit()
    conn.close()


def del_user():
    """
    删除所有用户
    :return: 
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM PWM_USER')
    cursor.close()
    conn.commit()
    conn.close()


def auth_user(password):
    """
    验证用户
    :param password: 
    :return: 
    """
    password = __get_md5(password)
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    result = cursor.execute('SELECT count(1) FROM PWM_USER WHERE PASSWORD=?', (password,))
    count = result.fetchone()[0]
    cursor.close()
    conn.commit()
    conn.close()
    return count != 0


def generate_key():
    """
    生成私钥和公钥
    :return: 公钥和私钥的元组
    """
    pass


def aes_encrypt(pwd, text):
    """
    使用aes进行加密，pwd和text都使用base64编码
    1 pwd使用utf-8编码转成bytes
    2 使用0填充密码
    3 原文使用utf-8编码转成bytes
    4 使用0填充原文
    5 加密
    6 使用base64编码
    7 使用utf-8解码
    :param pwd: 密码
    :param text: 原文
    :return: 密文（使用base64编码）
    """
    v1 = pwd.encode('utf-8')
    #print(v1)
    v2 = __fill_str(v1)
    #print(v2)

    encrypt = AES.new(__fill_str(pwd.encode('utf-8')), AES.MODE_CBC, iv)

    v3 = text.encode('utf-8')
    #print(v3)
    v4 = __fill_str(v3)
    #print(v4)
    v5 = encrypt.encrypt(v4)
    #print(v5)
    v6 = b64encode(v5)
    #print(v6)
    v7 = v6.decode('utf-8')
    #print(v7)

    return v7


def aes_decrypt(pwd, text):
    """
    使用aes进行解密，pwd使用base64编码，解密后需要用base64解码
    1 pwd使用utf-8编码成bytes
    2 使用0填充密码
    3 密文使用utf-8编码成bytes
    4 密文使用base64解码
    5 解密
    6 去掉0
    7 原文使用utf-8解码
    :param pwd: 密码
    :param text: 密文
    :return: 原文
    """
    v1 = pwd.encode('utf-8')
    #print(v1)
    v2 = __fill_str(v1)
    #print(v2)

    decrypt = AES.new(__fill_str(pwd.encode('utf-8')), AES.MODE_CBC, iv)

    v3 = text.encode('utf-8')
    #print(v3)
    v4 = b64decode(v3)
    #print(v4)
    v5 = decrypt.decrypt(v4)
    #print(v5)
    v6 = v5.rstrip(b'\0')
    #print(v6)
    v7 = v6.decode('utf-8')
    #print(v7)

    return v7


def __fill_str(s):
    return s + (16 - len(s) % 16) * b'\0'


def add_pwd(password, pwd, url, username, pwdtype='common'):
    """
    新增密码
    :param password: 源密码
    :param pwd: 密码
    :param url: 关联网址
    :param username: 用户名
    :param pwdtype: 密码类型
    :return: 
    """
    if (url or username) and pwd:
        is_exist = __exists(url, username, pwdtype)
        if not is_exist:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO PWM_INFO (URL,USERNAME,PASSWORD,TYPE) VALUES (?,?,?,?)',
                           (url, username, aes_encrypt(password, pwd), pwdtype))
            cursor.close()
            conn.commit()
            conn.close()
            return True, '新增成功'
        else:
            return False, '记录已存在'
    else:
        return False, '网址和用户名必须填写一个，密码必填'


def del_pwd(infoid):
    """
    根据id删除密码
    :param infoid: 记录id
    :return: 
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM PWM_INFO WHERE ID=?', (infoid,))
    cursor.close()
    conn.commit()
    conn.close()


def get_pwd(password, infoid):
    """
    获取解密后的记录
    :param password: 
    :param infoid: 
    :return: 
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    result = cursor.execute('SELECT ID,URL,USERNAME,PASSWORD,TYPE FROM PWM_INFO WHERE ID=?', (infoid,))
    ret = result.fetchall()
    data = None
    if len(ret) > 0:
        data = ret[0]
    cursor.close()
    conn.commit()
    conn.close()
    data = list(data)
    data[3] = aes_decrypt(password, data[3])
    return data


def list_info():
    """
    显示所有密码记录
    :return: url、username、type和id的namedtuple
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    result = cursor.execute('SELECT ID,URL,USERNAME,PASSWORD,TYPE FROM PWM_INFO')
    ret = result.fetchall()
    cursor.close()
    conn.commit()
    conn.close()
    return ret


def search_info(keyword):
    """
    根据keyword搜索记录
    :param keyword: 搜索关键字
    :return: 搜索结果
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    result = cursor.execute(
        'SELECT ID,URL,USERNAME,PASSWORD,TYPE FROM PWM_INFO WHERE URL=? AND USERNAME=?',
        (keyword, keyword))
    ret = result.fetchall()
    cursor.close()
    conn.close()
    return ret


def __exists(url, username, pwdtype):
    """
    判断记录是否存在
    :param url: 网址
    :param username: 用户名
    :param pwdtype: 类型
    :return: 是否存在
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    result = cursor.execute(
        'SELECT count(1) FROM PWM_INFO WHERE (URL=? OR URL IS NULL) AND (USERNAME=? OR USERNAME IS NULL) AND (TYPE=?)',
        (url, username, pwdtype))
    count = result.fetchone()[0]
    cursor.close()
    conn.close()
    return count != 0


def __get_md5(val):
    """
    MD5加密
    :param val: 
    :return: 
    """
    m = hashlib.md5()
    m.update(val.encode())
    return m.hexdigest()
