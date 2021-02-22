#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import uuid
import scoring
from http.server import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field():
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable
        self.value = None
        self.name = None

    def __set__(self, instance, value):
        try:
            if self.required is True and value is None:
                raise ValueError('required but not set')
            if self.nullable is False and not value:
                raise ValueError('couldn\'t be empty')
            if self.nullable is True and value is None:
                setattr(instance, self.name, None)
                return
            value = self.validate(value)
        except ValueError as e:
            raise ValueError('Field {}: {}'.format(self.name[1:], str(e))) from e
        setattr(instance, self.name, value)

    def validate(self, value):
        return value

    def __get__(self, instance, cls):
        return getattr(instance, self.name)

    def __set_name__(self, obj, name):
        self.name = '_' + name


class CharField(Field):
    def validate(self, value):
        if not isinstance(value, str):
            raise ValueError('not a string')
        return value


class ArgumentsField(Field):
    def validate(self, value):
        if not (isinstance(value, dict)):
            raise ValueError('Не словарь')
        return value


class EmailField(CharField):
    def validate(self, value):
        value = super().validate(value)
        if '@' not in value:
            raise ValueError('Нет @')
        return value


class PhoneField(Field):
    def validate(self, value):
        if not (isinstance(value, (int, str))):
            raise ValueError('Неправильного типа')
        phone = str(value)
        if len(phone) != 11 or phone[0] != '7':
            raise ValueError('Не телефон')
        return phone


class DateField(CharField):
    def validate(self, value):
        value = super().validate(value)
        date = datetime.datetime.strptime(value, '%d.%m.%Y').date()
        return date


class BirthDayField(DateField):
    def validate(self, value):
        date = super().validate(value)
        if (datetime.datetime.now().date() - date).days / 365 > 70:
            raise ValueError('Пора на пенсию')
        return date


class GenderField(Field):
    def validate(self, value):
        if not (isinstance(value, int) and 0 <= value <= 2):
            raise ValueError('На момент написания программы данный гендер был неизвестен')
        return value


class ClientIDsField(Field):
    def validate(self, value):
        if not isinstance(value, list) or not all(isinstance(cid, int) for cid in value):
            raise ValueError('Не список чисел')
        if len(value) == 0:
            raise ValueError('Список id не может быть пустым')
        return value


class ClientsInterestsRequest():
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, request, context, store):
        self.request = request
        self.context = context
        self.store = store

        self.client_ids = request.arguments.get('client_ids')
        self.date = request.arguments.get('date')

    def do(self):
        self.context["nclients"] = len(self.client_ids)
        interests = {cid: scoring.get_interests(self.store, cid)
                     for cid in self.client_ids}
        return interests


class OnlineScoreRequest():
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, request, context, store):
        self.request = request
        self.context = context
        self.store = store
        self.first_name = request.arguments.get('first_name')
        self.last_name = request.arguments.get('last_name')
        self.email = request.arguments.get('email')
        self.phone = request.arguments.get('phone')
        self.birthday = request.arguments.get('birthday')
        self.gender = request.arguments.get('gender')
        #  print('email: ', self.email)
        if ((self.phone is None or self.email is None)
                and (self.first_name is None or self.last_name is None)
                and (self.gender is None or self.birthday is None)):
            raise ValueError('Отсутствует хотя бы одна непустая пара в аргументах')

    def do(self):
        self.context["has"] = []
        for k, v in self.__class__.__dict__.items():
            if isinstance(v, Field) and getattr(self, k) is not None:
                self.context["has"].append(k)

        if self.request.is_admin:
            score = 42
        else:
            score = scoring.get_score(self.store,
                                      self.phone,
                                      self.email,
                                      birthday=self.birthday,
                                      gender=self.gender,
                                      first_name=self.first_name,
                                      last_name=self.last_name)
        return {"score": score}


class MethodRequest():
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def __init__(self, request):
        body = request['body']
        self.account = body.get('account')
        self.login = body.get('login')
        self.token = body.get('token')
        self.arguments = body.get('arguments')
        self.method = body.get('method')


def check_auth(request):
    if request.is_admin:
        msg = (datetime.datetime.now().strftime("%Y%m%d%H") +
               ADMIN_SALT).encode('utf-8')
        digest = hashlib.sha512(msg).hexdigest()
    else:
        msg = (request.account + request.login + SALT).encode('utf-8')
        digest = hashlib.sha512(msg).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    request_router = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest
    }

    try:
        request = MethodRequest(request)
        logging.debug('Request parsed correctly')
    except ValueError as e:
        return str(e), INVALID_REQUEST
    if not check_auth(request):
        return ERRORS[FORBIDDEN], FORBIDDEN

    try:
        method = request_router[request.method](request, ctx, store)
    except KeyError as e:
        return 'Method {} not found'.format(request.method), INVALID_REQUEST
    except ValueError as e:
        return str(e), INVALID_REQUEST
    response = method.do()
    return response, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers},
                        context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            logging.error(response)
            r = {"error": response or ERRORS.get(code, "Unknown Error"),
                 "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    logging.info("Server stopped")
