import { test, expect } from 'bun:test'
// beforeAll(async () => {
//     Bun.spawn(['bun', 'run', 'src/index.ts', '--https', '3000'])
//     await setTimeout(10_000)
// })
test('GET', async () => {
    const t = await fetch('http://localhost:8080/1', {
        method: 'GET',
        headers: {
            authorization: Bun.env.HAREDB_API_KEY!
        }
    })
    expect(await t.text()).toBe('1')
})