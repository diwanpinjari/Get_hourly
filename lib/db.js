const { createClient } = require('@libsql/client');

function localDatabase(filename) {
    // Load the native SQLite driver only for local development. Serverless
    // deployments use the hosted libSQL database and cannot load this binary.
    const sqlite3 = require('sqlite3').verbose();
    const raw = new sqlite3.Database(filename);
    raw.configure('busyTimeout', 5000);

    const api = {
        kind: 'local',
        run(sql, params = [], callback) {
            if (typeof params === 'function') { callback = params; params = []; }
            if (!callback) {
                return new Promise((resolve, reject) => raw.run(sql, params, function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes, lastID: this.lastID });
                }));
            }
            raw.run(sql, params, function(err) {
                callback.call(this, err);
            });
        },
        get(sql, params = [], callback) {
            if (typeof params === 'function') { callback = params; params = []; }
            raw.get(sql, params, (err, row) => callback?.(err, row));
        },
        all(sql, params = [], callback) {
            if (typeof params === 'function') { callback = params; params = []; }
            raw.all(sql, params, (err, rows) => callback?.(err, rows));
        },
        prepare(sql) {
            return {
                run(...params) { raw.run(sql, params); },
                finalize(callback) { callback?.(); }
            };
        },
        serialize(work) { work(); },
        configure() {},
        close(callback) { raw.close(callback); },
        async transaction(work) {
            await new Promise((resolve, reject) => raw.run('BEGIN IMMEDIATE', err => err ? reject(err) : resolve()));
            try {
                const result = await work(api);
                await new Promise((resolve, reject) => raw.run('COMMIT', err => err ? reject(err) : resolve()));
                return result;
            } catch (err) {
                await new Promise(resolve => raw.run('ROLLBACK', () => resolve()));
                throw err;
            }
        }
    };
    return api;
}

function remoteDatabase({ url, authToken }) {
    const client = createClient({ url, authToken });
    const execute = (sql, params = []) => client.execute({ sql, args: params });

    function resultCallback(callback, err, result) {
        if (!callback) {
            if (err) console.error('Database error:', err.message);
            return;
        }
        if (err) return callback(err);
        callback.call({
            changes: Number(result.rowsAffected || 0),
            lastID: Number(result.lastInsertRowid || 0)
        }, null);
    }

    function wrap(executor) {
        return {
            run(sql, params = [], callback) {
                if (typeof params === 'function') { callback = params; params = []; }
                if (!callback) {
                    return executor(sql, params).then(result => ({
                        changes: Number(result.rowsAffected || 0),
                        lastID: Number(result.lastInsertRowid || 0)
                    }));
                }
                executor(sql, params).then(result => resultCallback(callback, null, result)).catch(err => resultCallback(callback, err));
            },
            get(sql, params = [], callback) {
                if (typeof params === 'function') { callback = params; params = []; }
                executor(sql, params).then(result => callback?.(null, result.rows[0])).catch(err => callback?.(err));
            },
            all(sql, params = [], callback) {
                if (typeof params === 'function') { callback = params; params = []; }
                executor(sql, params).then(result => callback?.(null, result.rows)).catch(err => callback?.(err));
            },
            prepare(sql) {
                return {
                    run(...params) { executor(sql, params).catch(err => console.error('Database error:', err.message)); },
                    finalize(callback) { callback?.(); }
                };
            }
        };
    }

    const base = wrap(execute);
    const api = {
        kind: 'remote',
        client,
        ...base,
        serialize(work) { work(); },
        configure() {},
        close(callback) { client.close(); callback?.(); },
        async transaction(work) {
            const tx = await client.transaction('write');
            const txApi = wrap((sql, params) => tx.execute({ sql, args: params }));
            try {
                const result = await work(txApi);
                await tx.commit();
                return result;
            } catch (err) {
                await tx.rollback().catch(() => {});
                throw err;
            } finally {
                tx.close?.();
            }
        }
    };
    return api;
}

function createDatabase({ url, authToken, filename } = {}) {
    if (url) {
        if (!url.startsWith('file:') && !authToken) throw new Error('TURSO_AUTH_TOKEN is required for a remote database.');
        return remoteDatabase({ url, authToken });
    }
    return localDatabase(filename);
}

module.exports = { createDatabase };
