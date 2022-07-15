import flask
import pydantic
from flask import request, jsonify
from flask.views import MethodView
from flask_bcrypt import Bcrypt
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import uuid


app = flask.Flask('ads')
bcrypt = Bcrypt(app)
PG_DSN = 'postgresql://admin:12345@127.0.0.1:5432/flask_hw'
engine = create_engine(PG_DSN)
Base = declarative_base()
Session = sessionmaker(bind=engine)


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    user_name = Column(String(100), nullable=False, unique=True)
    password = Column(String(200), nullable=False)
    registration_time = Column(DateTime, server_default=func.now())

    def to_dict(self):
        return {
            'user_name': self.user_name,
            'registration_time': int(self.registration_time.timestamp()),
            'id': self.id,
        }

    def check_password(self, password: str):
        return bcrypt.check_password_hash(self.password.encode(), password.encode())


class Token(Base):
    __tablename__ = "tokens"
    id = Column(UUID(as_uuid=True), default=uuid.uuid4, primary_key=True)
    creation_time = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship(UserModel, lazy="joined")


class AdsModel(Base):
    __tablename__ = "ads"
    id = Column(Integer, primary_key=True)
    head = Column(String(200), nullable=False)
    body = Column(String(1000), nullable=False)
    creation_time = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship(UserModel, lazy="joined")

    def to_dict(self):
        return {
            'head': self.head,
            'body': self.body,
            'creation_time': int(self.creation_time.timestamp()),
            'id': self.id,
            'user_id': self.user_id
        }


Base.metadata.create_all(engine)


class CreateUserValidation(pydantic.BaseModel):
    user_name: str
    password: str

    @pydantic.validator('password')
    def strong_password(cls, value):
        if len(value) < 5:
            raise ValueError('too easy')
        return value


class HTTPError(Exception):
    def __init__(self, status_code: int, message):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HTTPError)
def error_handle(error):
    response = jsonify({"message": error.message})
    response.status_code = error.status_code
    return response


def check_token(session):
    token = (session.query(Token).filter(Token.id == request.headers.get('token')).first())
    if token is None:
        raise HTTPError(401, 'invalid token')
    return token


class AllUserView(MethodView):
    def get(self):
        users = []
        with Session() as session:
            for item in session.query(UserModel):
                users.append(item.to_dict())
        return flask.jsonify({'users': users})


class UserView(MethodView):
    def get(self, user_id: int):
        with Session() as session:
            token = check_token(session)
            if token.user.id != user_id:
                raise HTTPError(403, "auth error")
            return jsonify(token.user.to_dict())

    def post(self):
        try:
            validated_data = CreateUserValidation(**request.json).dict()
        except pydantic.ValidationError as err:
            raise HTTPError(400, err.errors())
        with Session() as session:
            validated_data['password'] = bcrypt.generate_password_hash(validated_data['password'].encode()).decode()
            new_user = UserModel(**validated_data)
            session.add(new_user)
            try:
                session.commit()
                return flask.jsonify(new_user.to_dict())
            except IntegrityError:
                user_name = validated_data['user_name']
                session.rollback()
                return flask.jsonify({'error': f'Username {user_name} already exists'})


@app.route('/login/', methods=['POST'])
def login():
    login_data = request.json
    with Session() as session:
        user = (
            session.query(UserModel)
            .filter(UserModel.user_name == login_data['user_name'])
            .first()
        )
        if user is None or not user.check_password(login_data['password']):
            raise HTTPError(401, 'incorrect user or password')
        token = Token(user_id=user.id)
        session.add(token)
        session.commit()
        return jsonify({'token': token.id})


class AllAdsView(MethodView):
    def get(self):
        ads = []
        with Session() as session:
            for item in session.query(AdsModel):
                ads.append(item.to_dict())
        return flask.jsonify({'ads': ads})


class AdsView(MethodView):
    def get(self, ads_id: int):
        with Session() as session:
            ads = session.query(AdsModel).filter(AdsModel.id == ads_id).first()
            return flask.jsonify(ads.to_dict())

    def post(self):
        new_ads_data = request.json
        with Session() as session:
            token = check_token(session)
            if token:
                new_ads = AdsModel(**new_ads_data, user_id=token.user_id)
                session.add(new_ads)
                session.commit()
                return flask.jsonify(new_ads.to_dict())

    def delete(self, ads_id: int):
        with Session() as session:
            token = check_token(session)
            ads = session.query(AdsModel).filter(AdsModel.id == ads_id).first()
            if token.user.id != ads.user_id:
                raise HTTPError(403, "auth error")
            else:
                for_del = session.query(AdsModel).get(ads_id)
                session.delete(for_del)
                session.commit()
                return flask.jsonify({'result': f'Ads {ads_id} deleted'})

    def patch(self, ads_id: int):
        with Session() as session:
            token = check_token(session)
            ads = session.query(AdsModel).filter(AdsModel.id == ads_id).first()
            if token.user.id != ads.user_id:
                raise HTTPError(403, "auth error")
            else:
                session.query(AdsModel).filter(AdsModel.id == ads_id).update(request.json)
                session.commit()
                upd_ads = session.query(AdsModel).get(ads_id)
                return flask.jsonify(upd_ads.to_dict())


app.add_url_rule('/user/<int:user_id>/', view_func=UserView.as_view('get_user'), methods=['GET'])
app.add_url_rule('/create_user/', view_func=UserView.as_view('create_user'), methods=['POST'])
app.add_url_rule('/user/', view_func=AllUserView.as_view('get_users'), methods=['GET'])
app.add_url_rule('/ads/', view_func=AllAdsView.as_view('get_ads'), methods=['GET'])
app.add_url_rule('/create_ads/', view_func=AdsView.as_view('create_ads'), methods=['POST'])
app.add_url_rule('/ads/<int:ads_id>/', view_func=AdsView.as_view('delete_ads'), methods=['DELETE'])
app.add_url_rule('/ads/<int:ads_id>/', view_func=AdsView.as_view('patch_ads'), methods=['PATCH'])
app.add_url_rule('/ads/<int:ads_id>/', view_func=AdsView.as_view('view_ads'), methods=['GET'])
