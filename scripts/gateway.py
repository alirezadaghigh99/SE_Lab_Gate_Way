import json
from functools import wraps
import jwt
from flask import Flask, request, session
from flask.json import jsonify
from requests.models import Response
from http import HTTPStatus
import datetime
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from flasgger import Swagger

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'
SWAGGER_TEMPLATE = {
    "securityDefinitions": {"APIKeyHeader": {"type": "apiKey", "name": "x-access-tokens", "in": "header"}}}
app.config['SWAGGER'] = {
    'title': 'Exp7 API'
}
swagger = Swagger(app, template=SWAGGER_TEMPLATE)


def decode_token(auth_token):
    try:
        payload = jwt.decode(auth_token, app.config["SECRET_KEY"], algorithms='HS256')
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        return "your token is expired, please try again"
    except jwt.InvalidTokenError:
        return "please login first"


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({"message": "token is missing, login first"}), HTTPStatus.UNAUTHORIZED
        try:
            username = decode_token(token)

        except Exception as e:
            return jsonify(message=str(e)), HTTPStatus.UNAUTHORIZED

        return f(username, *args, **kwargs)

    return decorator


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

        except Exception as e:
            print(e.__str__())
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
prescription_service = Service("Prescription Service", "127.0.0.1", 5002)
circuit_breaker = CircuitBreaker(10000, 3)


@app.route('/signup/<role>', methods=['POST'])
def signup(role):
    """signup users
    This is using docstrings for specifications.
    ---
      tags:
        - users
      parameters:
        - in: path
          name: role
          description: you should enter role of user(doctor or patient)
          required: true
          type: string


        - in: body
          name: user
          description: The user to create.
          schema:
            type: object
            required:
              - national_id
            required:
              - password
            required:
              - name


            properties:
              national_id:
                type: string
              password:
                type: string
              name:
                type: string

      responses:
        201:
          description: user created

        409:
          description: user already exists

        400:
          description: Bad request

    """
    json = request.json
    try:
        password = json.pop('password', None)

    except:
        return jsonify(message='Password is not given'), HTTPStatus.BAD_REQUEST

    json['hashed_passwd'] = generate_password_hash(password)
    response = circuit_breaker.send_request(requests.post, account_service, f"/create_user/{role}", json=json)
    return response.content, response.status_code, response.headers.items()


@app.route('/admin-signup', methods=['POST'])
def admin_signup():
    """signup admins
    This is using docstrings for specifications.
    ---
      tags:
       - users
      parameters:
        - in: body
          name: user
          description: The user to create.
          schema:
            type: object
            required:
              - username
            required:
              - password


            properties:
              username:
                type: string
              password:
                type: string

      responses:
        201:
          description: admin created

        409:
          description: user already exists

        400:
          description: Bad request

    """
    json = request.json
    try:
        password = json.pop('password', None)

    except:
        return jsonify(message='Password is not given'), HTTPStatus.BAD_REQUEST

    json['hashed_passwd'] = generate_password_hash(password)
    response = circuit_breaker.send_request(requests.post, account_service, "/create_admin", json=json)
    return response.content, response.status_code, response.headers.items()


@app.route('/signin/<role>', methods=['POST'])
def signin(role):
    """sign in users
    This is using docstrings for specifications.
    ---
      tags:
       - users
      parameters:
        - in: path
          name: role
          description: you should enter role of user(doctor or patient)
          required: true
          type: string
        - in: body
          name: user
          description: The user to create.
          schema:
            type: object
            required:
              - national_id
            required:
              - password


            properties:
              national_id:
                type: string
              password:
                type: string

      responses:
        200:
          description: user created

        409:
          description: user already exists

        400:
          description: Bad request

     """

    json = request.json
    try:
        n_id = json.get('national_id')
    except:
        return jsonify(message="national id is not given"), HTTPStatus.BAD_REQUEST

    try:
        password = json.get('password')
    except:
        return jsonify(message="Password is not given"), HTTPStatus.BAD_REQUEST
    user_url = f"/user/{role}/{n_id}"
    response = circuit_breaker.send_request(requests.get, account_service, user_url)
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
        session["role"] = role
        return jsonify(message="Login Successful", jwt=token), HTTPStatus.OK
    return jsonify(message='Invalid Password'), HTTPStatus.UNAUTHORIZED


@app.route('/admin-signin', methods=['POST'])
def admin_signin():
    """sign in admins
    This is using docstrings for specifications.
    ---
      tags:
       - users
      parameters:
        - in: body
          name: user
          description: The user to create.
          schema:
            type: object
            required:
              - username
            required:
              - password


            properties:
              username:
                type: string
              password:
                type: string

      responses:
        200:
          description: ok

        400:
          description: Bad request

    """

    json = request.json
    try:
        username = json.get('username')
    except:
        return jsonify(message="username is not given"), HTTPStatus.BAD_REQUEST

    try:
        password = json.get('password')
    except:
        return jsonify(message="Password is not given"), HTTPStatus.BAD_REQUEST
    user_url = f"/admin/{username}"
    response = circuit_breaker.send_request(requests.get, account_service, user_url)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()

    user = response.json()['user']
    expire_time = (datetime.datetime.now() + datetime.timedelta(days=1)).timestamp()
    if check_password_hash(user['hashed_passwd'], password):
        payload = {
            'sub': username,
            'exp': expire_time
        }
        token = jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
        return jsonify(message="Login as admin Successful", jwt=token), HTTPStatus.OK
    return jsonify(message='Invalid Password'), HTTPStatus.UNAUTHORIZED


@app.route('/doctors', methods=['GET'])
@token_required
def get_doctors(username):
    """get doctors by admins
    This is using docstrings for specifications.
    ---
      tags:
       - users
      security:
        - APIKeyHeader: ['x-access-tokens']
      responses:
        201:
          description: ok

        400:
          description: Bad request

    """
    success_url = "/show_doctors"
    response = circuit_breaker.send_request(requests.get, account_service, success_url, username)
    return response.content, response.status_code, response.headers.items()


@app.route('/patients', methods=['GET'])
@token_required
def get_patients(username):
    """get all patients detail by admins
    This is using docstrings for specifications.
    ---
      tags:
       - users
      security:
        - APIKeyHeader: ['x-access-tokens']
      responses:
        200:
          description: ok


        400:
          description: Bad request

    """
    success_url = "/show_patients"
    response = circuit_breaker.send_request(requests.get, account_service, success_url, username)
    return response.content, response.status_code, response.headers.items()


@app.route("/profile")
@token_required
def user_profile(username):
    """get userprofile by each user
    This is using docstrings for specifications.
    ---
      tags:
       - users
      security:
        - APIKeyHeader: ['x-access-tokens']
      responses:
        200:
          description: ok

        400:
          description: Bad request

    """
    success_url = "/user_profile"
    print(session["role"])
    data = {
        "username":username,
        'role':session["role"]
    }
    response = circuit_breaker.send_request(requests.get, account_service, success_url,data)
    return response.content, response.status_code, response.headers.items()


@app.route("/profile-admin")
@token_required
def admin_profile(username):
    """get profile admin by each admin
    This is using docstrings for specifications.
    ---
      tags:
       - users
      security:
        - APIKeyHeader: ['x-access-tokens   ']
      responses:
        200:
          description: ok

        400:
          description: Bad request

    """
    success_url = "/admin_profile"
    response = circuit_breaker.send_request(requests.get, account_service, success_url, username)
    return response.content, response.status_code, response.headers.items()


@app.route("/prescription", methods=['POST'])
@token_required
def create_prescription(username):
    """Create prescription
    This is using docstrings for specifications.
    ---
      tags:
       - prescription
      parameters:
        - in: body
          name: prescription
          description: The prescription to create.
          schema:
            type: object
            required:
              - patient_id
            required:
              - drug


            properties:
              patient_id:
                type: string
              drug:
                type: string
              comment:
                type: string

      security:
        - APIKeyHeader: ['x-access-tokens']
      responses:
        200:
          description: description created

        409:
          description: prescription already exists

        400:
          description: Bad request

     """
    if session['role'] != "doctor":
        return jsonify({"message": "you must be a doctor"}), HTTPStatus.UNAUTHORIZED

    data = request.json
    username_p = data["patient_id"]
    success_url = f"/user/patient/{username_p}"
    response = circuit_breaker.send_request(requests.get, account_service, success_url)
    if response.status_code != HTTPStatus.OK:
        return jsonify({"message": "this user not exists"})

    success_url = "/prescription"
    data = request.json
    data["doctor_id"] = username
    response = circuit_breaker.send_request(requests.post, prescription_service, success_url, json=data)
    return response.content, response.status_code, response.headers.items()


def append_profile_to_data(data, role, is_admin=False):
    id = data[f"{role}_id"]
    success_url = f"/user/{role}/{id}"
    response_user = circuit_breaker.send_request(requests.get, account_service, success_url)
    if response_user.status_code != HTTPStatus.OK:
        return response_user.content, response_user.status_code, response_user.headers.items()
    user_detected = response_user.json()["user"]
    if not is_admin:
        your_keys = ['name']
    else:
        your_keys = ['national_id', 'name']
    dict_you_want = {your_key: user_detected[your_key] for your_key in your_keys}
    dict_you_want["role"] = role
    data[f"{role}_profile"] = dict_you_want


@app.route('/prescriptions', methods=['GET'])
@token_required
def show_prescriptions(username):
    """Show prescriptions
    This is using docstrings for specifications.
    ---
      tags:
       - prescription
      security:
        - APIKeyHeader: ['x-access-tokens']
      responses:
        200:
          description: ok

        400:
          description: Bad request
     """
    success_url = f"/user/{session['role']}/{username}"
    response = circuit_breaker.send_request(requests.get, account_service, success_url)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()
    user = response.json()["user"]
    user_dic = {
        "role": session["role"],
        "national_id": user["national_id"]
    }
    get_prescription_url = "/prescription/query"
    response = circuit_breaker.send_request(requests.get, prescription_service,
                                            get_prescription_url, params=user_dic)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()
    opp_role = None
    if session["role"] == "doctor":
        opp_role = "patient"
    elif session["role"] == "patient":
        opp_role = "doctor"
    output = []
    for data in response.json():
        append_profile_to_data(data, opp_role)
        output.append(data)
    the_response = Response()
    the_response.status_code = response.status_code
    the_response._content = json.dumps(output).encode("utf-8")
    the_response.headers = response.headers
    return the_response.content, the_response.status_code, the_response.headers.items()


@app.route('/prescriptions/admin', methods=['GET'])
@token_required
def show_prescriptions_admin(username):
    """Show prescriptions to admin
    This is using docstrings for specifications.
    ---
      tags:
       - prescription
      security:
        - APIKeyHeader: ['x-access-tokens']
      responses:
        200:
          description: ok

        400:
          description: Bad request
     """
    success_url = f"/admin/{username}"
    response = circuit_breaker.send_request(requests.get, account_service, success_url)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()
    user_dic = {
        "role": "admin"
    }
    get_prescription_url = "/prescription/query"
    response = circuit_breaker.send_request(requests.get, prescription_service,
                                            get_prescription_url, params=user_dic)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()
    output = []
    for data in response.json():
        append_profile_to_data(data, "doctor", is_admin=True)
        append_profile_to_data(data, "patient", is_admin=True)
        output.append(data)
    the_response = Response()
    the_response.status_code = response.status_code
    the_response._content = json.dumps(output).encode("utf-8")
    the_response.headers = response.headers
    return the_response.content, the_response.status_code, the_response.headers.items()


@app.route('/daily', methods=['GET'])
@token_required
def show_stats_admin(username):
    """Show prescriptions to admin
    This is using docstrings for specifications.
    ---
      tags:
       - statistics
      parameters:
        - in: query
          name: day
          required: true
          schema:
            type: string
          description: (Example -> 20)
        - in: query
          name: month
          required: true
          schema:
            type: string
          description: (Example -> 12, 11)
        - in: query
          name: year
          required: true
          schema:
            type: string
          description: (Example -> 2021)
      security:
        - APIKeyHeader: ['x-access-tokens']
      responses:
        200:
          description: ok

        400:
          description: Bad request
     """
    success_url = f"/admin/{username}"
    response = circuit_breaker.send_request(requests.get, account_service, success_url)
    if response.status_code != HTTPStatus.OK:
        return response.content, response.status_code, response.headers.items()

    response_dict = {}
    get_prescription_url = "/prescription/stats"
    prescription_response = circuit_breaker.send_request(requests.get, prescription_service,
                                                         get_prescription_url, params=request.args)
    if prescription_response.status_code != HTTPStatus.OK:
        return prescription_response.content, prescription_response.status_code, prescription_response.headers.items()
    response_dict["prescription count"] = len(prescription_response.json())

    get_patient_url = "/patients/stats"
    patient_response = circuit_breaker.send_request(requests.get, account_service,
                                                    get_patient_url, params=request.args)
    if patient_response.status_code != HTTPStatus.OK:
        return patient_response.content, patient_response.status_code, patient_response.headers.items()
    response_dict["patient sign ups count"] = len(patient_response.json())

    get_doctor_url = "/doctors/stats"
    doctor_response = circuit_breaker.send_request(requests.get, account_service,
                                                   get_doctor_url, params=request.args)
    if doctor_response.status_code != HTTPStatus.OK:
        return doctor_response.content, doctor_response.status_code, doctor_response.headers.items()
    response_dict["doctor sign ups count"] = len(doctor_response.json())

    the_response = Response()
    the_response.status_code = prescription_response.status_code
    the_response._content = json.dumps(response_dict).encode("utf-8")
    the_response.headers = prescription_response.headers
    return the_response.content, the_response.status_code, the_response.headers.items()


@app.route("/")
def home():
    return 'hi'


if __name__ == "__main__":
    app.run(debug=True, port=5001, host="127.0.0.1")
