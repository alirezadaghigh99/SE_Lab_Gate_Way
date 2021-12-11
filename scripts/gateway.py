import jwt
from flask import Flask, request
from flask.json import jsonify
from requests.models import Response
from http import HTTPStatus
import datetime
import requests
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'


class Service:
    total_services = 0

    def __init__(self, name, address, port):
        self.name = name
        self.url = f"http://{address}:{port}"
        Service.total_services += 1
        self.id = Service.total_services


class ServiceState:
    def __init__(self):
        self.state = "c"
        self.last_attempt = 0
        self.num_of_failures = 0


class CircuitBreaker:
    def __init__(self, time_out, fc):
        self.time_out = time_out
        self.services = {}
        self.failure_count = fc

    def send_request(self, func, service, url, *args, **kwargs):
        if service.id in self.services:
            status = self.services[service.id]
            if status.state == 'o':
                if datetime.datetime.now() - status.last_attempt <= datetime.timedelta(milliseconds=self.time_out):
                    response = Response()
                    response.status_code = HTTPStatus.SERVICE_UNAVAILABLE
                    response._content = b"{'message' : 'Service is reloading...'}"
                    response.headers["Content-Type"] = 'application/json'
                    return response
                else:
                    status.state = 'h'
        else:
            status = self.services[service.id] = ServiceState()
        response = Response()
        try:
            status.last_attempt = datetime.datetime.now()
            uri = service.url + url

            response = func(uri, timeout=0.75, *args, **kwargs)
            if response.status_code in [500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 598, 599]:
                if status.state == 'o' or status.state == 'h':
                    status.state = 'o'
                else:
                    status.num_of_failures += 1
            else:
                if status.state == 'h':
                    status.state = 'c'
                    status.num_of_failures = 0

        except:
            status.num_of_failures += 1
            response = Response()
            response.status_code = HTTPStatus.SERVICE_UNAVAILABLE
            response._content = b"{'message' : 'service unavailable'}"
            response.headers["Content-Type"] = 'application/json'

        if status.num_of_failures >= self.failure_count:
            status.state = 'o'
            status.last_attempt = datetime.datetime.now()
        return response


account_service = Service("Account Service", "127.0.0.1", 5000)
circuit_breaker = CircuitBreaker(10000, 3)


@app.route('/signup', methods=['POST'])
def signup():
    json = request.json
    print(request.json)
    try:
        password = json.pop('password', None)

    except:
        return jsonify(message='Password is not given'), HTTPStatus.BAD_REQUEST

    json['hashed_passwd'] = generate_password_hash(password)
    response = circuit_breaker.send_request(requests.post, account_service, "/create_user", json=json)
    return response.content, response.status_code, response.headers.items()


@app.route('/signin', methods=['POST'])
def signin():
    json = request.json
    try:
        n_id = json.get('national_id')
    except:
        return jsonify(message="national id is not given"), HTTPStatus.BAD_REQUEST

    try:
        password = json.get('password')
    except:
        return jsonify(message="Password is not given"), HTTPStatus.BAD_REQUEST
    user_url = f"/user/{n_id}"
    response = circuit_breaker.send_request( requests.get,account_service, user_url)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()

    user = response.json()['user']
    expire_time = (datetime.datetime.now() + datetime.timedelta(days=1)).timestamp()
    if check_password_hash(user['hashed_passwd'], password):
        payload = {
            'sub': n_id,
            'exp': expire_time
        }
        token = jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
        return jsonify(message="Login Successful", jwt=token), HTTPStatus.OK
    return jsonify(message='Invalid Password'), HTTPStatus.UNAUTHORIZED


@app.route("/")
def home():
    return 'hi'
