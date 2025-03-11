import { Database, constants } from "bun:sqlite";

// prevents TS errors
declare var self: Worker;

let db: Database

self.onmessage = (event: MessageEvent) => {
    switch (event.data.action) {
        case 'STARTUP':
            db = new Database(event.data.path)
            db.fileControl(constants.SQLITE_FCNTL_PERSIST_WAL, 0);
            break;
        case 'SET':
            db.query(`INSERT OR REPLACE INTO key_value (key, value) VALUES (?, ?);`).run(event.data.key, event.data.value)
            postMessage({
                key: event.data.key,
                action: 'SET_DONE'
            })
            break;
        case 'DEL':
            db.query(`DELETE FROM key_value WHERE key = ?`).run(event.data.key)
            postMessage({
                key: event.data.key,
                action: 'DEL_DONE'
            })
            break;
        case 'SHUTDOWN':
            console.log('shutting down')
            db.close(false)
            postMessage({
                action: 'SHUTDOWN_DONE'
            })
            process.exit()
    }
}