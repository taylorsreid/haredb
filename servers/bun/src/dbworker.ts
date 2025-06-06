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
            break;
        case 'DEL':
            db.query(`DELETE FROM key_value WHERE key = ?`).run(event.data.key)
            break;
        case 'SHUTDOWN':
            db.close(false)
            process.exit()
    }
}