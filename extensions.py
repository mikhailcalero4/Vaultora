from models import db
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()
talisman = Talisman()
