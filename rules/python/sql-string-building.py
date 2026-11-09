import sqlite3

import sqlalchemy


def lookup(conn: sqlite3.Connection, user_id: str, table: str) -> None:
    cur = conn.cursor()
    # ruleid: python-sql-string-building
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: python-sql-string-building
    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
    # ruleid: python-sql-string-building
    cur.execute("SELECT * FROM users WHERE id = {}".format(user_id))
    # ruleid: python-sql-string-building
    conn.execute("DELETE FROM users WHERE id = " + user_id)
    # ruleid: python-sql-string-building
    conn.execute("SELECT * FROM users WHERE name = '" + user_id + "'")
    # ruleid: python-sql-string-building
    conn.executemany(table + " VALUES (?)", [(1,)])
    query = f"UPDATE users SET name = 'x' WHERE id = {user_id}"
    # ruleid: python-sql-string-building
    cur.execute(query)
    # ruleid: python-sql-string-building
    sqlalchemy.text(f"SELECT * FROM {table}")

    # ok: python-sql-string-building
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    # ok: python-sql-string-building
    cur.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
    # ok: python-sql-string-building
    cur.execute(f"SELECT 1")
    # ok: python-sql-string-building
    cur.execute("SELECT * FROM users " + "WHERE id = 1")
    fixed = "SELECT count(*) FROM users"
    # ok: python-sql-string-building
    cur.execute(fixed)
    # ok: python-sql-string-building
    print(f"looked up {user_id}")
