// Test fixture for semgrep --test: annotated examples, never built or run.
package fixture

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
)

type pgxPool interface {
	QueryRow(ctx context.Context, sql string, args ...any) any
	Exec(ctx context.Context, sql string, args ...any) (any, error)
}

func lookup(ctx context.Context, db *sql.DB, pool pgxPool, table, id string) {
	// ruleid: go-sql-string-building
	pool.QueryRow(ctx, fmt.Sprintf("SELECT 1 FROM %s WHERE tenant_id = $1", table), id)
	// ok: go-sql-string-building
	pool.QueryRow(ctx, "SELECT 1 FROM users WHERE tenant_id = $1", id)
	// ruleid: go-sql-string-building
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
	// ruleid: go-sql-string-building
	db.ExecContext(ctx, "DELETE FROM users WHERE id = '"+id+"'")
	q := fmt.Sprintf("SELECT count(*) FROM %s", table)
	// ruleid: go-sql-string-building
	db.QueryRowContext(ctx, q)
	// ok: go-sql-string-building
	db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)
	// ok: go-sql-string-building
	db.Exec("DELETE FROM users WHERE id = ?", id)
	// ok: go-sql-string-building
	fmt.Println(fmt.Sprintf("looked up %s", id))
}

func digests(data []byte) {
	// ruleid: go-weak-crypto
	md5.Sum(data)
	// ruleid: go-weak-crypto
	sha1.New()
	// ok: go-weak-crypto
	sha256.Sum256(data)
}

func handler(db *sql.DB, pool pgxPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		id := r.URL.Query().Get("id")
		name := r.FormValue("name")
		// ruleid: go-tainted-sql, go-sql-string-building
		db.QueryContext(ctx, "SELECT * FROM users WHERE id = "+id)
		query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
		// ruleid: go-tainted-sql, go-sql-string-building
		db.Query(query)
		// ok: go-tainted-sql
		db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)
		// ok: go-tainted-sql
		db.Query("SELECT * FROM users WHERE id = $1", id)
		// ruleid: go-tainted-sql, go-sql-string-building
		pool.Exec(ctx, "DELETE FROM users WHERE id = "+id)
		// ok: go-tainted-sql
		pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
		n, err := strconv.Atoi(r.FormValue("limit"))
		if err != nil {
			return
		}
		// The taint rule sees the parsed integer and stays quiet (an extra finding would fail the
		// test); the broader pattern rule still reports the Sprintf.
		// ruleid: go-sql-string-building
		db.Query(fmt.Sprintf("SELECT * FROM users LIMIT %d", n))

		host := r.PathValue("host")
		// ruleid: go-tainted-shell
		exec.CommandContext(ctx, "sh", "-c", "ping -c 1 "+host).Run()
		// ruleid: go-tainted-shell
		exec.Command("bash", "-c", fmt.Sprintf("nslookup %s", host)).Run()
		// ok: go-tainted-shell
		exec.CommandContext(ctx, "ping", "-c", "1", host).Run()
		// ok: go-tainted-shell
		exec.Command("sh", "-c", "uptime").Run()
	}
}
