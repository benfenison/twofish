'''
VenmoSession

Helper class for Venmo API

Usage example:

    >>> from venmo_session import VenmoSession
    >>> target_user_id = "some_user_id"
    >>> session = VenmoSession()
    >>> session.login("foo@bar.com", "password")
    >>> session.login_otp("xxxxxx")
    >>> session.send_money("target_user_id", 10.0, "some message", "xxxxxx", from_bank_if_exceeds=False)
    >>> session.logout()
'''


from venmo_api import random_device_id, AuthenticationFailedError, ApiClient, PaymentApi, UserApi
from venmo_api.models.exception import HttpCodeError,NotEnoughBalanceError
from venmo_api.models.payment_method import BankAccount


TWO_FACTOR_ERROR_CODE = 81109


class VenmoSession:

    api_client: ApiClient
    payment_api: PaymentApi
    user_api: UserApi
    device_id: str
    user_otp: str
    otp_secret: str
    access_token: str

    def __init__(self):
        self.api_client = ApiClient()
        self.payment_api = PaymentApi(None, self.api_client)
        self.user_api = UserApi(self.api_client)
        self.device_id = random_device_id()

    def login(self, username: str, password: str) -> dict:
        try:
            response = VenmoSession.authenticate_using_username_password(self.api_client, self.device_id, username, password)
        except HttpCodeError:
            return {
                "success": False,
                "description": "Incorrect username and password."
            }
        if response.get("status_code") == 401:
            self.otp_secret = response['headers'].get('venmo-otp-secret')
            VenmoSession.send_text_otp(self.api_client, self.device_id, self.otp_secret)
            return {
                "success": False,
                "description": "Need additional authentication. Provide OTP code via login_otp() method."
            }
        else:
            return {
                "success": True,
                "description": "Login success."
            }

    def login_otp(self, user_otp: str) -> dict:
        try:
            self.access_token = VenmoSession.authenticate_using_otp(self.api_client, self.device_id, user_otp, self.otp_secret)
        except AttributeError:
            return {
                "success": False,
                "description": "Not logged in. Call login method first."
            }

        self.api_client.update_access_token(access_token=self.access_token)
        try:
            VenmoSession.trust_this_device(self.api_client, self.device_id)
            return {
                "success": True,
                "description": "Login success."
            }
        except HttpCodeError:
            return {
                "success": False,
                "description": "Incorrect OTP code."
            }

    def logout(self) -> dict:
        try:
            VenmoSession.log_out(self.access_token)
        except AttributeError:
            return {
                "success": True,
                "description": "Not logged in. Nothing done."
            }
        return {
            "success": True,
            "description": "Logged out."
        }

    def send_money(self, target_user_id: str, amount: float, message: str, from_bank_if_exceeds: bool=False) -> dict:
        try:
            result = self.payment_api.send_money(
                    amount,
                    message,
                    target_user_id=target_user_id
            )
            return {
                "success": result,
                "description": "Sending %f to %s from Venmo balance." % (amount, target_user_id)
            }
        except NotEnoughBalanceError:
            if from_bank_if_exceeds:
                payment_methods = self.payment_api.get_payment_methods()
                for payment_method in payment_methods:
                    if type(payment_method) == BankAccount:
                        result = self.payment_api.send_money(
                                amount,
                                message,
                                target_user_id=target_user_id,
                                funding_source_id=payment_method.id
                        )
                        return {
                            "success": result,
                            "description": "Sending %f to %s from Bank account." % (amount, target_user_id)
                        }
            else:
                return {
                    "success": False,
                    "description": "Amount exceeded your Venmo balance."
                }
        return {
            "success": False,
            "description": "Some error occured."
        }

    def get_user_info(self) -> dict:
        try:
            me = self.user_api.get_my_profile()
        except HttpCodeError:
            return {
                "success": False,
                "description": "Not logged in. Call login method first."
            }
        return {
            "display_name": me.display_name,
            "id": me.id,
            "profile_picture_url": me.profile_picture_url
        }

    @staticmethod
    def authenticate_using_username_password(api_client: ApiClient, device_id: str, username: str, password: str) -> dict:
        resource_path = '/oauth/access_token'
        header_params = {'device-id': device_id,
                            'Content-Type': 'application/json',
                            'Host': 'api.venmo.com'
                            }
        body = {"phone_email_or_username": username,
                "client_id": "1",
                "password": password
                }

        return api_client.call_api(resource_path=resource_path, header_params=header_params,
                                            body=body, method='POST', ok_error_codes=[TWO_FACTOR_ERROR_CODE])

    @staticmethod
    def send_text_otp(api_client: ApiClient, device_id: str, otp_secret: str) -> dict:
        resource_path = '/account/two-factor/token'
        header_params = {'device-id': device_id,
                            'Content-Type': 'application/json',
                            'venmo-otp-secret': otp_secret
                            }
        body = {"via": "sms"}

        response = api_client.call_api(resource_path=resource_path, header_params=header_params,
                                                body=body, method='POST')

        if response['status_code'] != 200:
            reason = None
            try:
                reason = response['body']['error']['message']
            finally:
                raise AuthenticationFailedError(f"Failed to send the One-Time-Password to"
                                                f" your phone number because: {reason}")

        return response

    @staticmethod
    def authenticate_using_otp(api_client: ApiClient, device_id: str, user_otp: str, otp_secret: str) -> str:
        resource_path = '/oauth/access_token'
        header_params = {'device-id': device_id,
                            'venmo-otp': user_otp,
                            'venmo-otp-secret': otp_secret
                            }
        params = {'client_id': 1}

        response = api_client.call_api(resource_path=resource_path, header_params=header_params,
                                                params=params,
                                                method='POST')
        return response['body']['access_token']

    @staticmethod
    def trust_this_device(api_client: ApiClient, device_id: str):
        header_params = {'device-id': device_id}
        resource_path = '/users/devices'
        api_client.call_api(resource_path=resource_path,
                                    header_params=header_params,
                                    method='POST')

    @staticmethod
    def log_out(access_token: str) -> bool:
        resource_path = '/oauth/access_token'
        api_client = ApiClient(access_token=access_token)
        api_client.call_api(resource_path=resource_path,
                            method='DELETE')
        return True
