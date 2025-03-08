import Elysia, { error, redirect, t } from "elysia";
import HareDB from "./HareDB";

export { default } from './HareDB';

if (typeof Bun.env.HAREDB_SECRET_KEY === 'undefined') {
    throw new Error(`No HAREDB_SECRET_KEY environment variable is set. Please set it to continue.`);
}

const db: HareDB = new HareDB(Bun.env.HAREDB_PATH ?? 'hdb_persistence.sqlite', Bun.env.HAREDB_SECRET_KEY)

process.on('SIGINT', () => {
    console.log('\nHareDB server is shutting down. Zeroing out memory and closing database connection...')
    db.close()
    console.log('DONE')
    process.exit()
})

const DEFAULT_TCP_PORT: number = 1993

// if (Bun.argv.includes('--tcp') || (!Bun.argv.includes('--https') && !Bun.argv.includes('--ws'))) {

//     let host: string
//     let port: number
//     if (Bun.argv.includes('--tcp')) {
//         const maybeArgs: string[] = Bun.argv[Bun.argv.indexOf('--tcp') + 1].split(':')

//         const maybeHost: string = maybeArgs[0]
        

//         const maybePort: number | undefined = parseInt(maybeArgs[1])
//         if (!isNaN(maybePort)) {
//             port = maybePort
//         }
//         else if (typeof Bun.env.HAREDB_TCP_PORT !== 'undefined') {
//             port = parseInt(Bun.env.HAREDB_TCP_PORT)
//             if (isNaN(port)) {
//                 throw new Error(`Environment variable HAREDB_TCP_PORT is of type ${typeof Bun.env.HAREDB_HTTPS_PORT}. An integer was expected.`)
//             }
//         }
//         else {
//             port = DEFAULT_TCP_PORT
//         }
//     }
//     else {
//         host = 'localhost'
//         port = DEFAULT_TCP_PORT
//     }

//     Bun.listen({
//         hostname: "",
//         port: 0,
//         socket: {

//         }
//     })
// }

// if (Bun.argv.includes('--ws')) {
//     // create ws server
// }

if (Bun.argv.includes('--https')) {

    // 
    const maybePort: number = parseInt(Bun.argv[Bun.argv.indexOf('--https') + 1])
    let port: number

    if (!isNaN(maybePort)) { // check CLI args
        port = maybePort
    }
    else if (typeof Bun.env.HAREDB_HTTPS_PORT !== 'undefined') { // check environment variables
        port = parseInt(Bun.env.HAREDB_HTTPS_PORT)
        if (isNaN(port)) {
            throw new Error(`Environment variable HAREDB_HTTPS_PORT is of type ${typeof Bun.env.HAREDB_HTTPS_PORT}. An integer was expected.`)
        }
    }
    else { // use default
        port = 443
    }

    new Elysia()
        .onBeforeHandle(({ headers, request }) => {
            // reject insecure connections, force https if not in dev mode
            if (!request.url.startsWith('https') && Bun.env.NODE_ENV !== 'dev') {
                return redirect(request.url.replace('http', 'https'))
            }
            else if (headers.authorization !== Bun.env.HAREDB_API_KEY) {
                return error(401)
            }
        })

        .get('/:key', ({ params: { key } }) => {
            try {
                return db.get(key) ?? error(404)
            } catch (e) {
                // don't log e because it may contain sensitive data
                return error(500)
            }
        })

        .get('/:key/:value', ({ params: { key, value }, set }) => {
            try {
                if (db.set(key, value)) {
                    set.status = 204
                }
                else {
                    set.status = 201
                }
            } catch (e) {
                // don't log e because it may contain sensitive data
                return error(500)
            }
        })

        .post('/:key', ({ params: { key }, body, set }) => {
            try {
                if (db.set(key, body)) {
                    set.status = 204
                }
                else {
                    set.status = 201
                }
            } catch (e) {
                // don't log e because it may contain sensitive data
                return error(500)
            }
        }, {
            body: t.String()
        })

        .delete('/:key', ({ params: { key }, set }) => {
            try {
                if (db.del(key)) {
                    set.status = 204
                }
                else {
                    return error(404)
                }
            } catch (e) {
                // don't log e because it may contain sensitive data
                return error(500)
            }
        })

        .listen(port)
}