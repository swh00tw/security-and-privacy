from csv import reader
from app.util import hash

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def brute_force_attack(target_hash, target_salt):
    # TODO: return cracked password if one is found or None otherwise
    # for all common password
    # add salt and hash (use hash_pbkdf2) and see if it match the salted_hash(target hash)
    common_pwds = [x[0] for x in load_common_passwords()]
    for common_pwd in common_pwds:
        salted_hash = hash.hash_pbkdf2(common_pwd, target_salt)
        if salted_hash == target_hash:
            return common_pwd
    return None


def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    print(brute_force_attack(salted_creds[0][1], salted_creds[0][2]))

if __name__ == "__main__":
    main()
