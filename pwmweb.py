from flask import Flask, session, request, send_from_directory
import json
from funs import *

app = Flask(__name__)
app.secret_key = b'\xee\x87\xd8\xbfXp\xf0\xb4\xbd\xaf\xa21g\xdc\x8c\x9c\xe7\xa0\xaa]8\xf9A\x0c'


@app.route('/')
def index():
    # 修改成直接返回静态页面
    return send_from_directory('static/html', 'index.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    """
    用户登陆
    请求格式如下：
    {"password":"xxx"}
    :return: 
    """
    if request.method == 'GET':
        if session['is_login'] is None:
            return '{"status":false}'
        else:
            return '{"status":true}'
    else:
        req_data = request.get_data(as_text=True)
        data = json.loads(req_data)
        if auth_user(data['password']):
            session['is_login'] = True
            session['password'] = data['password']
            return '{"status":true,"msg":"登陆成功"}'
        else:
            return '{"status":false,"msg":"登陆失败"}'


# @app.route('/signin', methods=['POST'])
# def signin():
#     req_data = request.get_data(as_text=True)
#     data = json.loads(req_data)
#     #add_user(data['password'])
#     return '{"status":true,"msg":"注册成功"}'


@app.route('/logout')
def logout():
    """
    登出
    :return: 
    """
    session.pop('is_login', None)
    return '{"status":true,"msg":"退出成功"}'


@app.route('/pwd/list', methods=['POST'])
def pwd_list():
    if 'is_login' not in session:
        return '[]'
    req_data = request.get_data(as_text=True)
    if not req_data:
        return json.dumps(list_info())
    else:
        data = json.loads(req_data)
        return json.dumps(search_info(data['keyword']))


@app.route('/pwd/add', methods=['POST'])
def pwd_add():
    if 'is_login' not in session:
        return None
    req_data = request.get_data(as_text=True)
    data = json.loads(req_data)
    status, msg = add_pwd(session['password'], data['pwd'], data['url'], data['username'], data['type'])
    if status:
        return '{"status":true,"msg":"' + msg + '"}'
    else:
        return '{"status":false,"msg":"' + msg + '"}'


@app.route('/pwd/edit', methods=['POST'])
def pwd_edit():
    if 'is_login' not in session:
        return None
    req_data = request.get_data(as_text=True)
    data = json.loads(req_data)
    del_pwd(data['id'])
    status, msg = add_pwd(session['password'], data['pwd'], data['url'], data['username'], data['type'])
    if status:
        return '{"status":true,"msg":"修改成功"}'
    else:
        return '{"status":false,"msg":"' + msg + '"}'


@app.route('/pwd/del/<infoid>', methods=['GET'])
def pwd_del(infoid):
    if 'is_login' not in session:
        return None
    del_pwd(infoid)
    return '{"status":false,"msg":"删除成功"}'


@app.route('/pwd/get/<infoid>', methods=['GET'])
def pwd_get(infoid):
    if 'is_login' not in session:
        return None
    return json.dumps(get_pwd(session['password'], infoid))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
