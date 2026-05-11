#!/usr/bin/env bash
# postgres-replication-setup.sh
#
# SafeCadence — v10.7
# Sets up Postgres 16 streaming replication between a primary and a
# standby. Run this on each host as root.
#
# Two roles:
#   PRIMARY  — the node clients write to.
#   STANDBY  — read-only mirror, promoted on primary failure.
#
# Usage:
#   sudo ROLE=primary  ./postgres-replication-setup.sh
#   sudo ROLE=standby PRIMARY_HOST=10.0.0.5 ./postgres-replication-setup.sh
#
# Environment knobs:
#   ROLE            (required)         "primary" or "standby"
#   PRIMARY_HOST    (standby only)     IP of the primary
#   REPL_USER       (default: replicator)
#   REPL_PASS       (default: random, written to /root/.safecadence/repl.pass)
#   PG_DATA         (default: /var/lib/postgresql/16/main)
#   PG_CONF         (default: /etc/postgresql/16/main/postgresql.conf)
#   PG_HBA          (default: /etc/postgresql/16/main/pg_hba.conf)
#
# Done in roughly this order:
#   1.  Install Postgres 16 (apt).
#   2.  On primary: create replicator role, edit conf, restart, take base
#       backup directive for standby.
#   3.  On standby: stop pg, wipe data dir, pg_basebackup from primary,
#       drop in standby.signal, start pg.
#   4.  Verify on primary:
#       SELECT * FROM pg_stat_replication;

set -euo pipefail
ROLE="${ROLE:-}"
PG_DATA="${PG_DATA:-/var/lib/postgresql/16/main}"
PG_CONF="${PG_CONF:-/etc/postgresql/16/main/postgresql.conf}"
PG_HBA="${PG_HBA:-/etc/postgresql/16/main/pg_hba.conf}"
REPL_USER="${REPL_USER:-replicator}"
REPL_PASS="${REPL_PASS:-}"
PRIMARY_HOST="${PRIMARY_HOST:-}"

if [[ -z "$ROLE" ]]; then
    echo "ERROR: set ROLE=primary or ROLE=standby" >&2
    exit 1
fi

install_postgres () {
    if ! command -v psql >/dev/null; then
        apt-get update -qq
        apt-get install -y postgresql-16 postgresql-contrib
    fi
}

ensure_repl_pass () {
    install -d -m 700 /root/.safecadence
    if [[ -z "$REPL_PASS" ]]; then
        if [[ -f /root/.safecadence/repl.pass ]]; then
            REPL_PASS=$(cat /root/.safecadence/repl.pass)
        else
            REPL_PASS=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)
            echo "$REPL_PASS" > /root/.safecadence/repl.pass
            chmod 600 /root/.safecadence/repl.pass
        fi
    fi
}

primary () {
    install_postgres
    ensure_repl_pass

    # 1. Create replication role (idempotent)
    sudo -u postgres psql <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${REPL_USER}') THEN
        CREATE ROLE ${REPL_USER} WITH REPLICATION LOGIN ENCRYPTED PASSWORD '${REPL_PASS}';
    ELSE
        ALTER ROLE ${REPL_USER} WITH REPLICATION LOGIN ENCRYPTED PASSWORD '${REPL_PASS}';
    END IF;
END\$\$;
SQL

    # 2. postgresql.conf
    sed -i "s/^#*listen_addresses.*/listen_addresses = '*'/" "$PG_CONF"
    sed -i "s/^#*wal_level.*/wal_level = replica/" "$PG_CONF"
    sed -i "s/^#*max_wal_senders.*/max_wal_senders = 10/" "$PG_CONF"
    sed -i "s/^#*wal_keep_size.*/wal_keep_size = 512MB/" "$PG_CONF"
    sed -i "s/^#*hot_standby.*/hot_standby = on/" "$PG_CONF"

    # 3. pg_hba.conf — allow replicator from anywhere in the trusted subnet
    if ! grep -q "host replication ${REPL_USER}" "$PG_HBA"; then
        echo "host replication ${REPL_USER} 0.0.0.0/0 scram-sha-256" >> "$PG_HBA"
    fi

    systemctl restart postgresql

    echo "============================================"
    echo "Primary configured. Replication password is:"
    echo "  $REPL_PASS"
    echo "Stored at /root/.safecadence/repl.pass on this host."
    echo ""
    echo "On the standby, run:"
    echo "  ROLE=standby PRIMARY_HOST=$(hostname -I | awk '{print \$1}') \\"
    echo "    REPL_PASS=$REPL_PASS ./postgres-replication-setup.sh"
    echo "============================================"
}

standby () {
    if [[ -z "$PRIMARY_HOST" || -z "$REPL_PASS" ]]; then
        echo "ERROR: standby requires PRIMARY_HOST and REPL_PASS" >&2
        exit 1
    fi
    install_postgres

    systemctl stop postgresql
    rm -rf "$PG_DATA"
    install -d -o postgres -g postgres -m 700 "$PG_DATA"

    sudo -u postgres PGPASSWORD="$REPL_PASS" pg_basebackup \
        -h "$PRIMARY_HOST" -U "$REPL_USER" -D "$PG_DATA" \
        -P -R -X stream

    # pg_basebackup -R writes standby.signal + primary_conninfo for us.
    systemctl start postgresql

    echo "============================================"
    echo "Standby online. Verify on the primary with:"
    echo "  sudo -u postgres psql -c \"SELECT * FROM pg_stat_replication;\""
    echo "Expect one row with state='streaming'."
    echo "============================================"
}

case "$ROLE" in
    primary) primary ;;
    standby) standby ;;
    *) echo "Unknown ROLE=$ROLE" >&2; exit 1 ;;
esac
