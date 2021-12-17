

# python-jose
from jose import jwk, jwt
from jose.utils import base64url_decode
import base64
import json
import time
import hashlib
import hmac
import requests

userpool_id = ''
app_client_id = ''
app_client_secret = ''
region = ''
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
print(keys_url)
print("--------------------------------------------------- KEYS -----------------------------------------------------")
keys = requests.get(url=keys_url).json()['keys']
print(keys)
print("\n")

# Token se compone de 3 partes separadas por puntos
'''
Header -> Se decodifica de base64, aqui saldra kid y alg
Payload -> Se decodifica comparando keys con header (alg y kid) y luego usando kid. Es la data
Signature -> Combinacion header codificado y payload codificado con alg y kid(secret) y una firma
'''
def verify_token(token, keys, type):
    """Función que valida JWT. Siguiendo las indicaciones de la documentación de AWS.

    Args:
        token ([str]): Token a validar
        keys ([json]): Diccionario con las JWKS públicas del User Pool definido
        type ([str]): Tipo de token a validar (id, access)

    Returns:
        [json]: Datos decodificados del token. False en caso de error.
    """
    # keys = requests.get(url=keys_url).json()['keys']
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    # print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if type == "id":
        key_aud = 'aud'
    elif type == "access":
        key_aud = 'client_id'
    if claims[key_aud] != app_client_id:
        print('Token was not issued for this audience')
        return False
    # now we can use the claims
    print(claims)
    return claims


def run():
    login = ""
    password = ""
    url = F"https://cognito-idp.{region}.amazonaws.com/"

    # Hash para usar flujo USER_PASSWORD_AUTH
    message = bytes(login+app_client_id, 'utf-8')
    app_client_secret_bytes = bytes(app_client_secret, 'utf-8')
    secret_hash = base64.b64encode(
        hmac.new(app_client_secret_bytes, message, digestmod=hashlib.sha256).digest()).decode()

    body = {
        "AuthParameters": {
            "USERNAME": login,
            "PASSWORD": password,
            "SECRET_HASH": secret_hash
        },
        # EN Este caso es flujo para autenticar como admin
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": app_client_id
    }

    headers = {
        "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        "Content-Type": "application/x-amz-json-1.1"
    }

    response = requests.post(
        url=url, data=json.dumps(body), headers=headers)
    print("--------------------------------------------------- RESULT LOGIN COGNITO -----------------------------------------------------")
    print(response.text)
    print("\n")
    cognito_data = response.json()

    id_token = cognito_data['AuthenticationResult']['IdToken']
    access_token = cognito_data['AuthenticationResult']['AccessToken']

    # Se verifican id y access token
    verify_id_token = verify_token(id_token, keys, 'id')
    verify_ac_token = verify_token(access_token, keys, 'access')

if __name__ == "__main__":
    run()