import argparse
import google.auth
import google.auth.app_engine
import google.auth.compute_engine.credentials
import google.auth.iam
from google.auth.transport.requests import Request
import google.oauth2.credentials
import google.oauth2.service_account
import requests
import requests_toolbelt.adapters.appengine
from google.auth.exceptions import DefaultCredentialsError, RefreshError
from requests.exceptions import HTTPError, RequestException, ConnectionError

IAM_SCOPE = 'https://www.googleapis.com/auth/iam'
OAUTH_TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'

def get_service_account_token(client_id):
    """
    Get open id connect token for default service account.

    Returns:
        The open id connect token for default service account.
    """
    try:
        bootstrap_credentials, _ = google.auth.default(scopes=[IAM_SCOPE])
        validate_credentials(bootstrap_credentials)

        signer_email, signer = get_signer_and_email(bootstrap_credentials)
        service_account_credentials = google.oauth2.service_account.Credentials(
            signer,
            signer_email,
            token_uri=OAUTH_TOKEN_URI,
            additional_claims={'target_audience': client_id}
        )

        return get_google_open_id_connect_token(service_account_credentials), signer_email
    except DefaultCredentialsError as e:
        raise DefaultCredentialsError(f"Failed to obtain default credentials: {e}")

def validate_credentials(credentials):
    if isinstance(credentials, google.oauth2.credentials.Credentials):
        raise TypeError('This script is only supported for service accounts.')
    elif isinstance(credentials, google.auth.app_engine.Credentials):
        requests_toolbelt.adapters.appengine.monkeypatch()

def get_signer_and_email(credentials):
    try:
        credentials.refresh(Request())
        signer_email = credentials.service_account_email

        if isinstance(credentials, google.auth.compute_engine.credentials.Credentials):
            signer = google.auth.iam.Signer(Request(), credentials, signer_email)
        else:
            signer = credentials.signer

        return signer_email, signer
    except RefreshError as e:
        raise RefreshError(f"Failed to refresh credentials: {e}")

def get_google_open_id_connect_token(service_account_credentials):
    """
    Get an OpenID Connect token issued by Google for the service account.
    """
    try:
        service_account_jwt = (
            service_account_credentials._make_authorization_grant_assertion())
        request = google.auth.transport.requests.Request()
        body = {
            'assertion': service_account_jwt,
            'grant_type': google.oauth2._client._JWT_GRANT_TYPE,
        }
        token_response = google.oauth2._client._token_endpoint_request(
            request, OAUTH_TOKEN_URI, body)
        return token_response['id_token']
    except Exception as e:
        raise RuntimeError(f"Failed to obtain OpenID Connect token: {e}")

def make_request(url, token, data=None):
    headers = {'Authorization': f'Bearer {token}'}
    try:
        if data:
            response = requests.post(url, data=data, headers=headers)
        else:
            response = requests.get(url, headers=headers)
        
        response.raise_for_status()
        return response.text
    except HTTPError as e:
        if response.status_code == 403:
            raise PermissionError(
                'Service account does not have permission to access the IAP-protected application.')
        raise RuntimeError(f'Bad response from application: {e}')
    except ConnectionError as e:
        raise ConnectionError(f"Failed to connect to the application: {e}")
    except RequestException as e:
        raise RuntimeError(f"An error occurred during the request: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL of the host model')
    parser.add_argument('client_id', help='The client id used to setup IAP')
    parser.add_argument('--input', help='The input file.')
    args = parser.parse_args()

    try:
        token, signer_email = get_service_account_token(args.client_id)
        data = None

        if args.input:
            with open(args.input) as f:
                data = f.read()

        response = make_request(args.url, token, data)
        print(response)
    except (DefaultCredentialsError, PermissionError, ConnectionError, RuntimeError) as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
