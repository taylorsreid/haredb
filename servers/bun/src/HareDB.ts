import { Database } from "bun:sqlite";
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

export default class HareDB {

    private kv: {
        [key:string]: string
    }

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
            // create secret key standard buffer
            const unsafeSk: Buffer = Buffer.from(secretKey)
            sodium_mlock(unsafeSk) // keep out of swap

            // create secret key secured buffer
            this.sk = sodium_malloc(crypto_secretbox_KEYBYTES)
            sodium_mlock(this.sk) // keep secret key out of swap
            this.sk.set(unsafeSk)
            sodium_mprotect_noaccess(this.sk) // revoke all access to secret key unless specifically enabled

            // cleanup, unlock and zero out standard buffer since we're done with it
            sodium_munlock(unsafeSk)

            this.secure = true

            // TODO: fix
            // close process to close if unable to secure memory for the secret key
            if (!this.sk.secure) {
                console.error('Failed to secure memory for secret key. HareDB cannot run securely. Shutting down...')
                this.close()
                process.exit(1) // shutdown
            }
        }

        // in memory key value store
        this.kv = {}

        // sqlite persistent database
        const db: Database = new Database(dbPath, { create: true });
        db.exec("PRAGMA journal_mode = WAL;");

        // TODO: add config table with secure option
        db.exec(`
            CREATE TABLE IF NOT EXISTS config(
                key TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL
            );
        `)

        // store as text because Bun weirdly sometimes maps BLOBs to Buffers, and other times to Uint8Arrays unpredictably
        db.exec(`
            CREATE TABLE IF NOT EXISTS key_value(
                key TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL
            );
        `)
        db.query(`SELECT * FROM key_value;`).all().map((result) => {
            // all this just to make typescript play nice
            if (
                typeof result === 'object'
                && result !== null
                && 'key' in result
                && typeof result.key === 'string'
                && 'value' in result
                && typeof result.value === 'string'
            ) {
                this.kv[result.key] = result.value
                // result.key and result.value are already encrypted, so no need to lock memory or memzero anything here
            }
        })

        db.close()
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
        crypto_secretbox_easy(encryptedBuffer, unencryptedBuffer, nonce, this.sk)
        sodium_mprotect_noaccess(this.sk)

        // unlock and memzero the unencrypted buffer
        sodium_munlock(unencryptedBuffer)

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
        const inMemory: boolean = key in this.kv
        if (inMemory) {
            delete this.kv[key]
            this.worker.postMessage({
                action: 'DEL',
                key: key
            })
        }
        return inMemory
    }

    public close(): void {
        this.worker.postMessage({ action: 'SHUTDOWN' })
        sodium_mprotect_readwrite(this.sk) // allow read/write to secret key
        sodium_munlock(this.sk) // unlock secret key and memzero it
    }

}