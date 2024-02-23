from app.util.hash import PERFORMANCE_STATS
from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)
from app.models.breaches import get_breaches

from app.util.hash import (
    hash_pbkdf2,
    hash_sha256
)

def check_username_pwd_valid(db, username, password):
    plaintext_breaches, hashed_breaches, salted_breaches = get_breaches(db, username)
    if len(plaintext_breaches) == 0 and len(hashed_breaches) == 0 and len(salted_breaches) == 0:
        return True
    # check if user, password in plaintext breach
    for breach in plaintext_breaches:
        if password == breach.password:
            return False
    # check if user, password in hashed breach
    for breach in hashed_breaches:
        if hash_sha256(password) == breach.hashed_password:
            return False
    # check if user, password in slated_hash breach
    for breach in salted_breaches:
        if hash_pbkdf2(password, breach.salt) == breach.salted_password:
            return False
    return True
    
    

@get('/login')
def login():
    return template('login')

@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    print(user)
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        elif user.password != hash_pbkdf2(password, user.salt):
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login
    elif (request.forms.get("register")):
        # TODO: exercise 2.1
        if not check_username_pwd_valid(db, username, password):
            response.status = 401
            error = "The user and password pair is in breach dataset, use another username and password"
        elif user is not None:
            response.status = 401
            error = "{} is already taken.".format(username)
        else:
            create_user(db, username, password)
    else:
        response.status = 400
        error = "Submission error."
    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
    return template("login", error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")

@get('/stats')
def stats():
    return PERFORMANCE_STATS
