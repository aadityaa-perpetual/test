# enable dev mode
DEBUG = True

# define app dir
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config(object):
	SECRET_KEY = "secret"

class DevelopmentConfig(Config):	
	DEBUG = True
	WTF_CSRF_ENABLED = True
	SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProductionConfig(Config):
	DEBUG = True

app_config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}