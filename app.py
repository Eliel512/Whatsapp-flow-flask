import os
import logging
from flask import Flask, request #, Response
from flask_cors import CORS
# from flasgger import Swagger
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
from controller import chat_blueprint
# from views.api_docs import api_docs_blueprint
# from hvac_config import REDIS_HOST, REDIS_PASSWORD, REDIS_PORT

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing (CORS) for the app

# Initialize Swagger
# swagger = Swagger(app, template={
#     "swagger": "2.0",
#     "info": {
#         "title": "API Documentation",
#         "description": "Documentation of the SMS Chatbot API",
#         "version": "0.1.0"
#     },
#     "basePath": "/docs",
#     "schemes": ["https"],
# })

# Configure the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('gunicorn')

@app.before_request
def log_request_info():
    logger.info(f"Received request: {request.method} {request.url}")
    logger.info(f"Headers: {request.headers}")
    logger.info(f"Body: {request.get_data()}")

@app.after_request
def log_response_status(response):
    """Log the HTTP status code of each response."""
    app.logger.info(
        f"Client: {request.remote_addr} | Method: {request.method} | Endpoint: {request.path} | Status: {response.status_code}"
        )
    return response

@app.after_request
def add_global_no_cache_headers(response):
    response.headers['Cache-Control'] = "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
    response.headers['Pragma'] = "no-cache"
    response.headers['Expires'] = "0"

    return response


app.register_blueprint(chat_blueprint)

@app.route('/')
def home():
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=os.getenv('PORT', 5000))