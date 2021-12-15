
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from  werkzeug.security import generate_password_hash, check_password_hash
from flask_marshmallow import Marshmallow
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
ma = Marshmallow(app)


# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(80))

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id','public_id','name','email')
        model = User

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        data = request.json
        if 'token' in data:
            token = data['token']
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms="HS256")
            current_user = User.query.filter_by(public_id = data['public_id']).first()
            print(current_user)
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms="HS256")
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid !!'}), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = UserSchema().dump(users,many=True)
    return make_response(jsonify({'users': output}))


@app.route('/login', methods =['POST'])
def login():
    auth = request.json
    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response('Could not verify',401)
    user = User.query.filter_by(email = auth.get('email')).first()
    if not user:
        return make_response('Could not verify',401)
    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({'public_id': user.public_id,'exp' : datetime.utcnow() + timedelta(minutes = 30)}, app.config['SECRET_KEY'],algorithm='HS256')
        return make_response(jsonify({'token':token}), 201)
    return make_response('Could not verify',403)

# signup route
@app.route('/signup', methods =['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # checking for existing user
    user = User.query.filter_by(email = email).first()
    if not user:
        # database ORM object
        user = User(public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            password = generate_password_hash(password,method='sha256')
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        return make_response('User already exists. Please Log in.', 202)

if __name__ == "__main__":
    app.run(debug = True)
