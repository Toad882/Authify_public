# Authify

Authify is a robust and flexible authentication provider (IdP) designed to manage user authentication for third-party websites, similar to "Login with Google." The system is built to be secure, scalable, and easy to integrate.

---

## Features

- **OAuth2 Protocol Support**: Seamless integration with web and mobile applications.
- **Multi-Factor Authentication (MFA)**: Offers TOTP and passkey authentication methods.
- **Role-Based Access Control (RBAC)**: Fine-grained user permissions management.
- **Heroku Ready**: Optimized for deployment and management on Heroku.
- **Developer-Friendly SDKs**: Python and JavaScript SDKs for rapid integration.
- **Advanced Security**: Implements CSRF protection, XSS mitigation, HTTPS-only communication, brute force protection, and DDoS mitigation.
- **User Management**: Includes a dashboard for user and role management.

---

## Project Objectives

- Centralize authentication for third-party websites.
- Enhance security with multi-factor authentication.
- Provide an intuitive interface for administrators and developers.
- Enable access monitoring and auditing.
- Support a wide range of client applications, including legacy systems.
- Simplify deployment with comprehensive documentation and SDKs.

---

## System Architecture

- **Backend**: Built with Python using secure frameworks like Flask.
- **Frontend**: Developed for an interactive and user-friendly experience.
- **Database**: MongoDB for efficient and scalable data management.
- **Deployment**: Fully configured for Heroku, compatible with Docker and Kubernetes.

---

## Key Functionalities

### Authentication
- **Credential Options**: Supports username/password, TOTP, and passkey authentication.
- **Login Flow**:
  - Users choose their preferred authentication method.
  - TOTP or passkey satisfies multi-factor authentication requirements.
  - Upon successful login, users are redirected to their dashboard or authorization screen.

### Monitoring & Security
- **Audit Logs**: Tracks login attempts and administrative actions.
- **Advanced Security Features**:
  - CSRF token validation.
  - Strict HTTPS-only policy.
  - Brute force and DDoS attack mitigation.

---

## Getting Started

### Prerequisites
- [Python 3.9+](https://www.python.org/downloads/)

## Installation
### Local Development
See the notes below for limitations and known issues.
1. Clone the repository:
   ```bash
   git clone https://github.com/Toad882/Authify_public.git
   cd authify
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
3. Install backend dependencies:
    ```bash
    pip install -r requirements.txt
4. Configure environment variables in .env files for backend.

### Running the Application
1. Start the backend server:
   ```bash
   git clone https://github.com/Toad882/Authify_public.git
   cd authify
### Deployment on Heroku
1. Create a Heroku app:
    ```bash
    heroku create your-app-name
2. Push the repository:
    ```bash
    git push heroku main
3. Set up required environment variables on Heroku (HOSTNAME, MONGODB_URI, MONGO_USERNAME, MONGO_PASSWORD, SECRET_KEY):
    ```bash
    heroku config:set VAR_NAME=value
## API Examples
### Token Endpoint
URL: /token   
Method: POST  
Description: Issues an OAuth2 token
#### Request Parameters
| Parameter       | Type   | Required | Description                                                                 |
|-----------------|--------|----------|-----------------------------------------------------------------------------|
| `grant_type`    | String | Yes      | The type of OAuth2 flow (e.g., `authorization_code`).                      |
| `client_id`     | String | Yes      | The unique identifier of the client application.                           |
| `client_secret` | String | Yes      | The secret key associated with the client application.                     |
| `redirect_uri`  | String | Yes      | The URI to which the authorization code was originally sent.               |
| `code`          | String | Yes      | The authorization code received from the authorization step.               |
| `csrf_token`    | String | Yes      | A token to prevent CSRF attacks.                                           |

#### Request Example:
    
      POST /token
      Content-Type: application/x-www-form-urlencoded
      
      client_id=example_client_id&client_secret=example_secret&grant_type=authorization_code&redirect_uri=https://example.com/callback&code=example_code
#### Response Example
    
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600
    }
### Authorization Endpoint
URL: /authorize  
Method: GET  
Description: Handles user authorization requests, including OAuth2 flows
#### Request Parameters
| Parameter      | Type   | Required | Description                                                                 |
|----------------|--------|----------|-----------------------------------------------------------------------------|
| `client_id`    | String | Yes      | The unique identifier of the client application.                           |
| `redirect_uri` | String | Yes      | The URI where the user will be redirected after authorization.             |
| `scope`        | String | Yes      | The access permissions requested by the client application.                |
| `state`        | String | Yes      | A random string to maintain state between the request and the callback.    |
| `response_type`| String | Yes      | The type of response requested (e.g., `code` for authorization code flow). |
| `confirm`      | String | Optional | Indicates whether the user confirms (`yes`) or denies (`no`) the request.  |

#### Request Example
    
      GET /authorize?client_id=example_client_id
          &redirect_uri=https://example.com/callback
          &scope=read_write
          &state=xyz123
          &response_type=code HTTP/1.1
      Host: authify.example.com
#### Response Examples
##### User Grants Authorization

The server redirects the user to the provided redirect_uri with an authorization code and the state parameter.
    
      HTTP/1.1 302 Found
      Location: https://example.com/callback?code=authorization_code&state=xyz123
##### User Denies Authorization

The server redirects the user to the provided redirect_uri with an error message.
    
      HTTP/1.1 302 Found
      Location: https://example.com/callback?error=access_denied&state=xyz123
##### Invalid Request

If the request is invalid (e.g., missing parameters), the server responds with an error.
    
      HTTP/1.1 400 Bad Request
      Content-Type: application/json
      
      {
        "error": "invalid_request",
        "error_description": "The 'client_id' parameter is missing or invalid."
      }
## Known Issues
### Limitations
If local development is preferred, the following limitations should be considered:
- Passkey authentication is not supported in the local environment.
- No VPN should be used while running the application if an online database is used.
- The LOCAL environment variable should be set to True in the .env file.
## Roadmap
### Future Enhancements
Decentralization: Multi-backend system for higher availability.
SAML 2.0 Support: Increase compatibility with enterprise systems.
AI-Driven Security: Suspicious login detection and personalized user experiences.
Improved Testing: Automated end-to-end testing for all new builds.
## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any bug fixes or enhancements.

## License
This project is licensed under the Apache 2.0 License. See the LICENSE file for details.

