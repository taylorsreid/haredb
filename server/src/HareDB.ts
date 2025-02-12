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

interface KeyValue {
    [key:string]: string
}

export default class HareDB {

    private kv: KeyValue
    private db: Database
    private sk: SecureBuffer

    constructor(dbPath: string, secretKey: string) {

        // in memory key value store
        this.kv = {}

        // sqlite persistent database
        this.db = new Database(dbPath, { create: true });
        this.db.exec("PRAGMA journal_mode = WAL;");

        // store as text because Bun weirdly sometimes maps BLOBs to Buffers, and other times to Uint8Arrays unpredictably
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS key_value(
                key TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL
            );
        `)
        this.db.query(`SELECT * FROM key_value;`).all().map((result) => {
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

        // close process to close if unable to secure memory for the secret key
        if (!this.sk.secure) {
            console.error('Failed to secure memory for secret key. HareDB cannot run securely. Shutting down...')
            this.close()
            process.exit(1) // shutdown
        }
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

    public set(key: string, value: string): void {
        key = this.encrypt(key)
        value = this.encrypt(value)
        this.kv[key] = value
        this.db.query(`INSERT OR REPLACE INTO key_value (key, value) VALUES (?, ?);`).run(key, value)
    }

    public get(key: string): string | null {
        key = this.encrypt(key) // both keys and values are stored in memory and at rest encrypted
        const fromKv: string | undefined = this.kv[key] // search memory for key value pair
        if (fromKv) {
            return this.decrypt(fromKv)
        }
        // it may be in the database even if it's not in memory if multiple local instances of HareDB are running
        const fromDb = this.db.query(`SELECT value FROM key_value WHERE key = ?`).get(key) as { value: string } | null
        if (fromDb) {
            this.kv[key] = fromDb.value // put it in memory for future get calls
            return this.decrypt(fromDb.value)
        }
        return null // non existent
    }

    public del(key: string): boolean {
        key = this.encrypt(key)
        const inMemory: boolean = typeof this.kv[key] !== 'undefined'
        if (inMemory) {
            delete this.kv[key]
        }
        return inMemory || this.db.query(`DELETE FROM key_value WHERE key = ?`).run(key).changes > 0
    }

    public close(): void {
        sodium_mprotect_readwrite(this.sk) // allow read/write to secret key
        sodium_munlock(this.sk) // unlock secret key and memzero it
        this.db.close()
    }

}