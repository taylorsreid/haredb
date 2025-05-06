import { Database, constants } from "bun:sqlite";
import {
    crypto_secretbox_easy,
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_open_easy,
    sodium_malloc,
    sodium_mlock,
    sodium_mprotect_noaccess,
    sodium_mprotect_readonly,
    sodium_mprotect_readwrite,
    sodium_munlock,
    type SecureBuffer
} from "sodium-native";

interface KeyValue {
    [key: string]: string
}

export default class HareDB {

    private kv: KeyValue

    private worker: Worker

    public sk: SecureBuffer

    private _secure: boolean;

    public get secure(): boolean {
        return this._secure;
    }
    private set secure(value: boolean) {
        this._secure = value;
    }

    /**
     * 
     * @param dbPath 
     * @param secretKey 
     */
    constructor(dbPath: string, secretKey?: string) {

        // safe shutdown handler
        process.on('exit', () => {
            this.close()
        })

        if (secretKey) {
            const unsafeSk: Buffer = Buffer.from(secretKey) // create secret key standard buffer
            sodium_mlock(unsafeSk) // keep out of swap
            Bun.gc(true) // collect garbage to remove unecrypted secretKey string
            this.sk = sodium_malloc(crypto_secretbox_KEYBYTES) // create secret key secured buffer
            sodium_mlock(this.sk) // keep secret key out of swap
            this.sk.set(unsafeSk)
            sodium_mprotect_noaccess(this.sk) // revoke all access to secret key unless specifically enabled
            sodium_munlock(unsafeSk) // cleanup, unlock and zero out standard buffer since we're done with it
            if (!this.sk.secure) { // force close if unable to secure memory for the secret key
                this.close()
                throw new Error('Failed to secure memory for secret key. HareDB cannot run securely. Shutting down...')
            }
            Bun.unsafe.gcAggressionLevel(1) // TODO: TEST PERFORMANCE IMPACT
            this.secure = true
        }
        else {
            this.secure = false
        }

        this.kv = {} // in memory key value store

        // create persistent database and set up schema
        // store kv's as text because Bun weirdly sometimes maps BLOBs to Buffers, and other times to Uint8Arrays unpredictably
        const db: Database = new Database(dbPath, { create: true, strict: true, });
        db.fileControl(constants.SQLITE_FCNTL_PERSIST_WAL, 0);
        db.exec(`
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS key_value (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);
        `)
        db.prepare(`
            INSERT OR IGNORE INTO meta (key, value) VALUES
            ('create_language', 'ts_bun'), ('version', :version), ('secure', :secure), ('create_time', :now);
        `)
            .run({
                version: Bun.env.npm_package_version ?? '0.0.0',
                secure: `${this.secure}`,
                now: `${Math.round(Date.now() / 1000)}`
            })

        // check for security settings mismatch
        if (this.secure !== ((db.prepare(`SELECT value FROM meta WHERE key = 'secure';`).get() as { value: string }).value === 'true')) {
            throw new Error(this.secure ?
                `Configuration error, an encryption key was provided in the constructor, but the persistence file '${dbPath}' is not set to use encryption. For security purposes, these two must match. Consider creating a new database file to use encryption, or omit the secretKey argument in the constructor to use the existing unencrypted database.`
                : `Configuration error, an encryption key was not provided in the constructor, and the persistence file ${dbPath} is set to use encryption. Provide the encryption key to decrypt and use this database.`
            )
        }

        if (this.secure) {
            db.prepare(`INSERT OR IGNORE INTO meta (key, value) VALUES ('secure_test_string', ?);`).run(this.encrypt('ENCRYPTED TEXT'))
            try {
                this.decrypt((db.prepare(`SELECT value FROM meta WHERE key = 'secure_test_string';`).get() as {value: string}).value) // throws on failure
            } catch (error) {
                throw new Error('Decryption error, the provided encryption key is not correct.')
            }
        }

        // load all keys in persistent storage into memory
        db.prepare(`SELECT * FROM key_value;`).all().map((result) => {
            // result.key and result.value are already encrypted, so no need to lock memory or memzero anything here
            this.kv[(result as KeyValue).key] = (result as KeyValue).value
        })
        
        // close local db now that synchronous startup work is complete and offload all further work to a worker thread
        db.close(false)
        this.worker = new Worker('./src/dbworker.ts')
        this.worker.postMessage({
            action: 'STARTUP',
            path: dbPath
        })
    }

    private encrypt(value: string): string {
        // create message secure buffer
        const unencryptedBuffer: Buffer = Buffer.from(value)
        sodium_mlock(unencryptedBuffer) // keep out of swap

        // create other variables
        const encryptedBuffer: Buffer = Buffer.alloc(unencryptedBuffer.length + crypto_secretbox_MACBYTES)
        const nonce: Buffer = Buffer.alloc(crypto_secretbox_NONCEBYTES)

        // briefly allow secret key access, encrypt, then revoke secret key access again
        sodium_mprotect_readonly(this.sk)
        crypto_secretbox_easy(encryptedBuffer, unencryptedBuffer, nonce, this.sk) // encryptedBuffer is mutated in place
        sodium_mprotect_noaccess(this.sk)
        sodium_munlock(unencryptedBuffer) // unlock and memzero the unencrypted buffer

        return JSON.stringify(Array.from(encryptedBuffer))
    }

    private decrypt(value: string): string {
        const encrypted: Buffer = Buffer.from(JSON.parse(value))
        const decrypted: Buffer = Buffer.alloc(encrypted.length - crypto_secretbox_MACBYTES)
        sodium_mprotect_readonly(this.sk)
        const success: boolean = crypto_secretbox_open_easy(decrypted, encrypted, Buffer.alloc(crypto_secretbox_NONCEBYTES), this.sk)
        sodium_mprotect_noaccess(this.sk)
        if (success) {
            return decrypted.toString()
        }
        throw new Error('Unable to decrypt a value, has the encryption key changed?')
    }

    // TODO: MOVE THIS TO CLI TOOL, TOO MANY POTENTIAL RACE CONDITIONS
    // public changeKey(newKey: string): HareDB {
    //     // console.log('CHANGE KEY CALLED')
    //     if (!this.secure) {
    //         throw new Error('not in secure mode')
    //     }
    //     Bun.file(this.dbPath).delete()
    //     const newHdb: HareDB = new HareDB(this.dbPath, newKey)
    //     for (const [key, value] of Object.entries(this.kv)) {
    //         newHdb.set(this.decrypt(key), this.decrypt(value))
    //     }
    //     this.close() // automatically calls gc
    //     return newHdb
    // }

    /**
     * Set a key value pair to be stored in memory and persisted on disk.
     * Persistent file system operations happen in a separate worker thread and are non-blocking.
     * @param key the string "name" to store the value under.
     * @param value the string value assigned to the key.
     * @returns true if an existing key/value pair was updated, false if it was newly created.
     */
    public set(key: string, value: string): boolean {
        if (this.secure) {
            key = this.encrypt(key)
            value = this.encrypt(value)
        }
        const exists: boolean = key in this.kv
        this.kv[key] = value
        this.worker.postMessage({
            action: 'SET',
            key: key,
            value: value
        })
        return exists
    }

    /**
     * Get the value associated with the given key.
     * @param key the string "name" that the value is stored under.
     * @returns a string representation of the value associated with the given key, or null if there is no value set for the given key.
     */
    public get(key: string): string | null {

        if (this.secure) {
            key = this.encrypt(key) // both keys and values are stored in memory and at rest encrypted
        }

        const value: string | undefined = this.kv[key]

        if (value && this.secure) { // encrypted
            return this.decrypt(value)
        }
        else if (value) { // unencrypted
            return value
        }
        else { // non existent
            return null
        }
    }

    /**
     * Delete the key/value pair from the in memory database and persistent storage.
     * Persistent file system operations happen in a separate worker thread and are non-blocking.
     * @param key the string "name" that the value is stored under.
     * @returns true if the key/value pair existed in memory, false if not.
     */
    public del(key: string): boolean {
        if (this.secure) {
            key = this.encrypt(key)
        }
        const exists: boolean = key in this.kv
        if (exists) {
            delete this.kv[key]
            this.worker.postMessage({
                action: 'DEL',
                key: key
            })
        }
        return exists
    }

    /**
     * 
     */
    public close(): void {
        if (this.worker) { // undefined if decryption of test string fails in the constructor
            this.worker.postMessage({ action: 'SHUTDOWN' })
        }
        if (this.secure) {
            sodium_mprotect_readwrite(this.sk) // allow read/write to secret key
            sodium_munlock(this.sk) // unlock secret key and memzero it
            Bun.gc(true) // force garbage collection just in case
        }
    }

}