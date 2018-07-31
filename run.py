import os
from app.auth.auth_api import UserRegister
from app import create_app
from flask_restful import Api

config_name = os.getenv('FLASK_CONFIG')
app = create_app(config_name)
api = Api(app=app, prefix="/api/v1")

api.add_resource(UserRegister, "/auth/register")
# if __name__ == '__main__':
#     app.run()

app.run(host='0.0.0.0', port=8080, debug=True)