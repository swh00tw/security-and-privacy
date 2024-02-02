from csv import reader

from app.models.breaches import (
    create_plaintext_breach_entry,
    create_hashed_breach_entry,
    create_salted_breach_entry
)

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
SALTED_HASHED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_breaches(db):
    with open(PLAINTEXT_BREACH_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        for creds in r:
            create_plaintext_breach_entry(db, creds[0], creds[1])

    # TODO: Add logic for other types of breaches
    creds = load_breach(HASHED_BREACH_PATH)
    for usr, hashed_pwd in creds:
        create_hashed_breach_entry(db, usr, hashed_pwd)
    creds = load_breach(SALTED_HASHED_BREACH_PATH)
    for usr, salted_hash, salt in creds:
        create_salted_breach_entry(db, usr, salted_hash, salt)



