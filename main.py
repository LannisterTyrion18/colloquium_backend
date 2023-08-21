from flask import Flask, request, Response, json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from flask_bcrypt import Bcrypt
from flask_jwt_extended import jwt_required, set_access_cookies, unset_jwt_cookies, create_access_token, JWTManager, get_jwt_identity
from datetime import timedelta

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///colloquium.sqlite"
app.config['JWT_SECRET_KEY'] = "colloquium.ai"
app.config['JWT_COOKIE_SECURE'] = False

"""
TODO: 
- migrate: open flask shell and db.create_all() - check inside code
- setup other endpoints
"""


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    

@app.route("/api/users", methods=["GET", "POST"])
def user():
    # login 
    if request.method == "GET":
        data = request.form

        user = User.query.filter_by(email=data['email']).first()

        if not user:
            return Response(status=400, response=json.dumps({"message": "User does not exist"}))
        

        if not bcrypt.check_password_hash(user.password, data['password']):
            return Response(status=400, response=json.dumps({"message": "Invalid password"}))
        
        access_token = create_access_token(identity=user.email, expires_delta=timedelta(minutes=60))

        response = Response(status=200, response=json.dumps({"message": "Login successfull"}))
        set_access_cookies(response, access_token) # set jwt

        return response

    # sign user up      
    elif request.method == "POST":
        data = request.form
        
        if data["password"] != data["confirm_password"]:
            return Response(status=400, response=json.dumps({"message": "Passwords do not match"}))

        user = User(data['email'], bcrypt.generate_password_hash(data['password']).decode("utf-8"))
        try:
            db.session.begin()
            db.session.add(user)
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            return Response(status=400, response=json.dumps({"message": "Email already exists"}))
        
        return Response(status=200, response=json.dumps({"message": "Successfully created user"}))
    
@app.route("/api/logout", methods=["POST"])
@jwt_required
def logout():
    response = Response(status=201, response=json.dumps({"message": "Logout Successfull"}))
    unset_jwt_cookies(response)
    return response

@jwt.expired_token_loader
def expired():
    return Response(status=401, response=json.dumps({"message": "Session expired"})) # redirect to login page

if __name__ == "__main__":
    app.run(debug=True)

