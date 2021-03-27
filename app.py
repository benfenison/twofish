import secrets
from typing import Union

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import jwt

from venmo_session import VenmoSession



TOKEN_LENGTH = 128
MAX_TRANSFER_LIMIT = 99.999999999


app = FastAPI(
    title="Twofish API",
    version="v1",
)
session_dict = dict()


class SessionModel(BaseModel):
    session_id: str


class CredentialsModel(SessionModel):
    session_id: str
    username: str
    password: str


class OtpModel(SessionModel):
    otp_code: str


class UserInfoModel(SessionModel):
    display_name: str
    id: str
    profile_picture_url: str


class MoneyTransferModel(SessionModel):
    target_user_id: str
    amount: float
    message: str


class ResponseModel(SessionModel):
    success: bool
    description: str


@app.get("/")
def hello():
    return { "message": "Welcome to Twofish API" }


@app.get('/api/v1/session')
def get_session_id():
    session_id = secrets.token_urlsafe(TOKEN_LENGTH)
    session_dict[session_id] = VenmoSession()
    return SessionModel(session_id=session_id)


@app.post('/api/v1/login')
def login(body: CredentialsModel) -> ResponseModel:
    session = session_dict.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail='no session found for the session_id')
    result = session.login(body.username, body.password)
    result['session_id'] = body.session_id
    return ResponseModel(**result)


@app.post('/api/v1/login_otp')
def login_otp(body: OtpModel) -> ResponseModel:
    session = session_dict.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail='no session found for the session_id')
    result = session.login_otp(body.otp_code)
    result['session_id'] = body.session_id
    return ResponseModel(**result)


@app.post('/api/v1/logout')
def logout(body: SessionModel) -> ResponseModel:
    session = session_dict.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail='no session found for the session_id')
    result = session.logout()
    session_dict.pop(body.session_id)
    del session
    result['session_id'] = body.session_id
    return ResponseModel(**result)


@app.post('/api/v1/me')
def get_user_info(body: SessionModel) -> Union[ResponseModel, UserInfoModel]:
    session = session_dict.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail='no session found for the session_id')
    result = session.get_user_info()
    result['session_id'] = body.session_id
    if result.get('id') == None:
        return ResponseModel(**result)
    return UserInfoModel(**result)


@app.post('/api/v1/send_money')
def send_money(body: MoneyTransferModel) -> ResponseModel:
    session = session_dict.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail='no session found for the session_id')
    if body.amount > MAX_TRANSFER_LIMIT:
        result = {
            "success": False,
            "description": "Maximum transferring limit exceeded. Try smaller amount."
        }
    else:
        result = session.send_money(body.target_user_id, body.amount, body.message)
    result['session_id'] = body.session_id
    return ResponseModel(**result)
