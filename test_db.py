import psycopg2

def test_conn():
    guesses = ['', 'postgres', '1234', 'root', 'admin']
    for pwd in guesses:
        try:
            conn = psycopg2.connect(dbname='postgres', user='postgres', password=pwd, host='localhost')
            print(f'Success with password: {pwd}')
            return
        except Exception as e:
            pass
    print('Failed all standard guesses.')

test_conn()
