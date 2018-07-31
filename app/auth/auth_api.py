from flask_restful import Resource, reqparse, marshal
from ..models import User
from .. import db
from flask import make_response, jsonify
class UserRegister(Resource):
	"""
	Rgister user
	"""
	def post(self):
		parser = reqparse.RequestParser()
		parser.add_argument("email", required=True, help="Please enter email")
		parser.add_argument("username", required=True, help="Please enter username")
		parser.add_argument("first_name", required=True, help="Please enter first_name")
		parser.add_argument("last_name", required=True, help="Please enter last_name")
		parser.add_argument("password", required=True, help="Please enter password")

		data = parser.parse_args()
		
		try:
			user = User(email=data['email'],
		                username=data['username'],
		                first_name=data['first_name'],
		                last_name=data['last_name'],
		                password=data['password']
                		)

			if user.find_by_email(data['email']):
				responseObject = {
					'status': 'fail',
					'message': 'User {} already exists'.format(data['email']),
				}
				return responseObject, 202

			if user.find_by_username(data['username']):
				responseObject = {
					'status': 'fail',
					'message': 'User {} already exists'.format(data['username']),
				}
				return responseObject, 202

			# add User to the database
			db.session.add(user)
			db.session.commit()

			auth_token = user.encode_auth_token(user.id)

			responseObject = {
				'status': 'success',
				'message': 'Successfully registered.',
				'auth_token': auth_token.decode()
			}
			return responseObject, 201
		except Exception as e:
			responseObject = {
				'status': 'fail',
				'message': 'User already exists. Please Log in.',
			}
			return responseObject, 202