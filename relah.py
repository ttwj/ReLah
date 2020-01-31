# Python implementation of DBS PayLah!
# By ttwj - 2017
import base64
import random
import string

#remember to install pycryptodome!

import datetime
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

import lxml.etree, json
from lxml import html
from pprint import pprint
from io import StringIO
import requests
import re
import time
import warnings
import requests
import contextlib

from api.models import PayLahAPISource

http_proxy = "http://localhost:8888"
https_proxy = "https://localhost:8888"

app_ver = '4.0.0'

proxyDict = {
    "http": http_proxy,
    'https': https_proxy
}

try:
    from functools import partialmethod
except ImportError:
    # Python 2 fallback: https://gist.github.com/carymrobbins/8940382
    from functools import partial


    class partialmethod(partial):
        def __get__(self, instance, owner):
            if instance is None:
                return self

            return partial(self.func, instance, *(self.args or ()), **(self.keywords or {}))


@contextlib.contextmanager
def no_ssl_verification():
    old_request = requests.Session.request
    requests.Session.request = partialmethod(old_request, verify=False)

    warnings.filterwarnings('ignore', 'Unverified HTTPS request')
    yield
    warnings.resetwarnings()

    requests.Session.request = old_request


from Crypto.Cipher import AES
from Crypto import Random




class AESCipher:
    def __init__(self, key):
        """
        Requires hex encoded param as a key
        """
        self.key = key.encode()

    BLOCK_SIZE = 16

    def pkcs5_pad(self, s):
        """
        padding to blocksize according to PKCS #5
        calculates the number of missing chars to BLOCK_SIZE and pads with
        ord(number of missing chars)
        @see: http://www.di-mgt.com.au/cryptopad.html
        @param s: string to pad
        @type s: string
        @rtype: string
        """
        return s + (self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE) * chr(self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE)

    def encrypt(self, raw):
        """
        Returns hex encoded encrypted value!
        """
        raw = self.pkcs5_pad(raw)
        iv = '1234567898765432'.encode()
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.encrypt(raw.encode('utf-8'))

    def decrypt(self, enc):
        """
        Requires hex encoded param to decrypt
        """
        enc = enc.decode("hex")
        iv = enc[:16]
        enc = enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc))


class DBSPayLahTransaction(object):
    rand = ''
    public_key_bin = ''
    cipher = None


    def updatePayLahAPISource(self):
        self.payLahAPISource.api_random = self.rand
        self.payLahAPISource.api_base64_public_key = self.base64_public_key

    def __init__(self, payLahAPISource):
        self.payLahAPISource = payLahAPISource

        """
        api_random = models.CharField(max_length=20)
    api_base64_public_key = models.TextField()
    api_deviceID = models.CharField(max_length=100)
    api_phoneID = models.CharField(max_length=100)
    api_encryptedPasscode = models.TextField()
    api_unencryptedPasscodeLength = models.IntegerField()
    api_cookiesJSON = JSONField()

        """

        self.ipAddress = payLahAPISource.api_ipAddress
        self.rand = payLahAPISource.api_random
        self.base64_public_key = payLahAPISource.api_base64_public_key
        self.deviceID = payLahAPISource.api_deviceID
        self.phoneID = payLahAPISource.api_phoneID
        self.encryptedPasscode = payLahAPISource.api_encryptedPasscode
        self.public_key_bin = base64.b64decode(payLahAPISource.api_base64_public_key.encode('utf-8'))
        self.unencryptedPasscodeLength = str(payLahAPISource.api_unencryptedPasscodeLength)
        self.cipher = AESCipher(self.rand)
        self.r = requests.session()
        self.r.cookies = requests.utils.cookiejar_from_dict(payLahAPISource.api_cookiesJSON)

    #def __init__(self):
    #    self.r = requests.Session()

    def ran_generator(size=16, chars=string.ascii_letters + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def get_server(self):
       payload = {
                'appID': 'DBSMobileWallet',
                'appver': app_ver,
                'channel': 'rc',
                'ipAddress': self.ipAddress,
                'platform': 'iPhone',
                'serviceID': 'getServer'
            }

       data = self.requestLah(payload)
       self.public_key_bin = base64.b64decode(data['base64EncodedString'].encode('utf-8'))

       print(data)



    def requestLah(self, payload):

        import requests
        import logging

        # These two lines enable debugging at httplib level (requests->urllib3->http.client)
        # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
        # The only thing missing will be the response.body which is not logged.
        try:
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client
        #http_client.HTTPConnection.debuglevel = 1

        # You must initialize logging, otherwise you'll not see debug output.
        #logging.basicConfig()
        #logging.getLogger().setLevel(logging.DEBUG)
        #requests_log = logging.getLogger("requests.packages.urllib3")
        #requests_log.setLevel(logging.DEBUG)
        #requests_log.propagate = True

        with no_ssl_verification():
            r = self.r.post("https://p2pcweb.dbs.com/services/DBSMobileWalletService0/" + payload['serviceID'], data=payload,
                             #proxies=proxyDict,
                              headers={
                                  'user-agent': 'PayLah/7 CFNetwork/808.2.16 Darwin/16.3.0',

                              })
        data = json.loads(r.text)

        return data

    def encrypt(self, text):
        return base64.b64encode(self.cipher.encrypt(text))


    def prelogin(self):
        payload = {
            'appID': 'DBSMobileWallet',
            'appver': app_ver,
            'channel': 'rc',
            'ipAddress': self.ipAddress,
            'deviceId': self.encrypt(self.deviceID),
            'loginType': 'wallet',
            'platform': 'iPhone',
            'serviceID': 'prelogin',
        }

        print(payload)

        self.requestLah(payload)




    def generate_paylah_url(self, amount, reservation_id, retry=False):


        payload = {
            'appID': 'DBSMobileWallet',
            'appver':  app_ver,
            'channel': 'rc',
            'channelIndicator': 'P2P',
            'count': self.encrypt('20'),
            'ipAddress': self.ipAddress,
            'deviceId': self.encrypt(self.deviceID),
            'isOneTimeOnly': self.encrypt('Y'),
            'payment_name': self.encrypt('BeepPay PayLah ' + reservation_id),
            'periodOfSale': self.encrypt('7'),
            'price': self.encrypt(amount),
            'phoneId': self.encrypt(self.phoneID),
            'phoneModel': 'iPhone 5s',
            'platform': 'iPhone',
            'serviceID': 'generatePaylahURL',

        }

        print(payload)

        data = self.requestLah(payload)

        if data['statusCode'] != '0000':
            if retry is False:
                print("PayLah expired, regenerating")

                # TODO: save this particulars somewhere in the model :-)

                self.retry_paylah_login()

                return self.generate_paylah_url(amount, reservation_id, retry=True)
            else:
                raise Exception('Exceeded login retries')

        print(data)

        return data


    def retry_paylah_login(self):

        '''

                            self.rand = payLahAPISource.api_random
                       self.base64_public_key = payLahAPISource.api_base64_public_key
                       self.deviceID = payLahAPISource.api_deviceID
                       self.phoneID = payLahAPISource.api_phoneID
                       self.encryptedPasscode = payLahAPISource.api_encryptedPasscode
                       self.public_key_bin = base64.b64decode(payLahAPISource.api_base64_public_key.encode('utf-8'))
                       self.unencryptedPasscodeLength = str(payLahAPISource.api_unencryptedPasscodeLength)
                       self.cipher = AESCipher(self.rand)
                       self.r = requests.session()
                       self.r.cookies = requests.utils.cookiejar_from_dict(payLahAPISource.api_cookiesJSON)


                       '''

        self.get_server()
        # transaction.public_key_bin = base64.b64decode("MIICqDCCAZACCGNAYXyIwSRhMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAMMCkRCUyBQYXlsYWgwHhcNMTcxMDI3MTczMTEyWhcNMTkxMDI4MTczMTEyWjAYMRYwFAYDVQQDDA1EQlMgTWVyY2hhbnRzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhQ2CljVoM6GrAWrxN0qh9dgVLwpTcFsC2C3uKecRFCDODZY3Qv/DL8ta8+ZN+UWmvHCt/tWjt7FCCIolfn1iXyPuldngsey/JKTSmhPL1imufPUJjbUZaTSwpP1y7DWWJGLqqZMdtyaq0KkpxDM8rBgmXm9eC+YQ+woDux2SQp4PlCpnjxXpYoXG55CWjLsQLx1AaVOFjH38do13OIvEMJWucfmDgY4k6l8TT9gxKoGXTN7p9rHK57dVDOLTScspjuOazU6nLM0U5obsQAvjEzMzKo4wDESremQYWlcaKT4gOliSwbOy4EF6XBrtU+JC7jGPWAOpx/evRUecfKgR9wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAyjzuSQB2LMLe24TsNHO7zqpdxl4TQ1fd6B7+E1klKPn/pcWgVQZkgsOyjH+LY7P+yk5LVUyGBukuH8qQUY2LWqo8Si1dJeSJzRSKfMElZj1idMx04X9YiJHvpq4eRaqjXtmsXRgc7bD3TlE6ZZa1GwVWux67IdfhCb/9pnfY37d9G6xM0Tk2UkxTc+WfXLG8k1RX6HhjQ8vTNJhkMTb/TwZfLQ89owPKzSahCpk9qKj9TU4uuDJXmAmiuf6IKCXL+mvGeltc/NDGetvsSwUCkBfkpuRoiS4mHkdGn+4w3izgobByjAgQMNpK4l7qLuonmHLDFkE92tX/yn4bJxqGy".encode('utf-8'))
        self.wallet_launch()
        self.prelogin()
        self.wallet_login_new()

        self.payLahAPISource.api_random = self.rand
        self.payLahAPISource.api_base64_public_key = self.base64_public_key
        self.payLahAPISource.api_deviceID = self.deviceID
        self.payLahAPISource.api_phoneID = self.phoneID
        self.payLahAPISource.api_encryptedPasscode = self.encryptedPasscode
        self.payLahAPISource.api_unencryptedPasscodeLength = self.unencryptedPasscodeLength
        self.payLahAPISource.api_cookiesJSON = requests.utils.dict_from_cookiejar(self.r.cookies)
        self.payLahAPISource.save()


    def get_paymentlink_expired_history(self):
        payload = {
            'appID': 'DBSMobileWallet',
            'appver': app_ver,
            'channel': 'rc',
            'channelIndicator': 'P2P',
            'count': self.encrypt('50'),
            'ipAddress': self.ipAddress,
            'deviceId': self.encrypt(self.deviceID),
            'index': self.encrypt('0'),
            'phoneId': self.encrypt(self.phoneID),
            'phoneModel': 'iPhone 5s',
            'platform': 'iPhone',
            'serviceID': 'getPaymentLinkHistoryExpired',

        }

        return self.requestLah(payload)


    def get_transaction_history(self, retry=False):
        payload = {
            'appID': 'DBSMobileWallet',
            'appver': app_ver,
            'channel': 'rc',
            'channelIndicator': 'P2P',
            'count': self.encrypt('80'),
            'ipAddress': self.ipAddress,
            'deviceId': self.encrypt(self.deviceID),
             'index': self.encrypt('1'),
            'loginType': '02',
            'phoneId': self.encrypt(self.phoneID),
            'phoneModel': 'iPhone 5s',
            'platform': 'iPhone',
            'serviceID': 'getTransactionHistory',

        }



        print(payload)

        data = self.requestLah(payload)

        if data['statusCode'] != '0000':
            if retry is False:
                print("PayLah expired, regenerating")

                # TODO: save this particulars somewhere in the model :-)

                self.retry_paylah_login()

                return self.get_transaction_history(retry=True)
            else:
                raise Exception('Exceeded login retries')

        print(json.dumps(data))

        return data

    def force_paylink_expire(self, transactionRef):

        payload = {
            'appID': 'DBSMobileWallet',
            'appver': app_ver,
            'channel': 'rc',
            'channelIndicator': 'P2P',
            'deviceId': self.encrypt(self.deviceID),
            'expiryDays': self.encrypt('EXPIRY'),
            'ipAddress': self.ipAddress,
            'isOneTime': self.encrypt('Y'),
            'status': self.encrypt('E'),
            'transactionRefNumber': self.encrypt(transactionRef),
            'platform': 'iPhone',
            'serviceID': 'updatePaymentLink',
            'isOnetime': self.encrypt('Y'),
        }

        print(payload)

        return self.requestLah(payload)


    def wallet_login_new(self):

        payload = {
            'appID': 'DBSMobileWallet',
            'appver': app_ver,
            'channel': 'rc',
            'channelIndicator': 'P2P',
            'count': self.encrypt('10'),
            'ipAddress': self.ipAddress,
            'deviceId': self.encrypt(self.deviceID),
            'encryptedPassCode': self.encryptedPasscode,
            'index': self.encrypt('1'),
            'loginType': '02',
            'phoneId': self.encrypt(self.phoneID),
            'phoneModel': 'iPhone 5s',
            'platform': 'iPhone',
            'serviceID': 'walletloginNew',
            'touchIDStatus': 'Active',
            'unencryptedPasscodelength': self.unencryptedPasscodeLength
        }

        print(payload)

        return self.requestLah(payload)


    def wallet_launch(self):

        self.rand = DBSPayLahTransaction.ran_generator()
        #self.rand = "QCos1rgim225kkrE"
        self.cipher = AESCipher(self.rand)

        public_key = RSA.import_key(self.public_key_bin)

        cipher_rsa = PKCS1_v1_5.new(public_key)
        cipher_text = cipher_rsa.encrypt(self.rand.encode())
        print(cipher_text)
        #print("random " + self.rand)
        #print(self.public_key_bin)

        encoded = base64.b64encode(cipher_text)

        #encoded = "RrdSu8k31vXLdCctxUrXK+YNdJVyy/x9fUC3Z322Ku4/2GsGWqJty4H/1Z6XTnkTkKjcuCmRYcBce5NBnroBcyCIrWrlfG3H+xTYU/vuRylQjvFopIHAhvp8KZ1myR2dhghUMCoKmzr2tZyT9Ay4GHEPfLYzIdtivpNnJNjpM8LTe+4n/cMLtBLuLdZiiDH/OLLuenKxieS4pl9YTMeG3pxAuGWZk5D2qccOy8SEH7H2D+JJzu7GX+WM0GPTMDoxvYwOifaLxvcM5qJoZ8AInso54dOdV+jytIDfnO2aHaksTqLMFLOeiYST8puKOAIfWpSuDl+Yr3knMiz5Dq3cXw=="

        print("encoded " + str(encoded))

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        payload = {
            'appID': 'DBSMobileWallet',
            'appver': app_ver,
            'channel': 'rc',
            'deviceId': self.encrypt(self.deviceID),
            'encryptedAES128Key': '',
            'encryptedDeviceModel': self.encrypt('iPhone 5s'),
            'encryptedOs': self.encrypt('iPhone'),
            'fromWalletType': self.encrypt('02'),
            'inputParam': encoded,
            'ipAddress': self.ipAddress,
            'phoneId': self.encrypt(self.phoneID),
            'platform': 'iPhone',
            'searchCriteria': 'deviceID',
            'searchParam': self.encrypt(self.deviceID),
            'serviceID': 'walletLaunch',
            'subscriptionId': '',
            'timeStamp': timestamp,
            'toWalletType': self.encrypt('00')
        }

        print(payload)

        self.requestLah(payload)


#paylah_api_source = PayLahAPISource.objects.get(pk=1)
#txn = DBSPayLahTransaction(paylah_api_source)
#txn.get_transaction_history()
