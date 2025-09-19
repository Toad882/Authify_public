from auth import CustomAuthorizationCodeGrant, query_client, save_token
from auth import CustomAuthorizationServer

oauth = CustomAuthorizationServer()

def create_oauth(app):
    global oauth
    oauth.init_app(
        app,
        query_client=query_client,
        save_token=save_token
    )
    oauth.register_grant(CustomAuthorizationCodeGrant)
    return oauth