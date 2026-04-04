# Control Status Query — TCP Mode

## Auth Protocol
- Python 3.12 `multiprocessing.connection` uses `{sha256}` prefixed challenges
- HMAC digest: sha256
- Mutual auth: server challenges client, then client challenges server
- Auth key: SHA-256 of transport identity private key (or explicit rpc_key)

## Wire Format
- Messages are 4-byte big-endian length prefix + payload
- Auth messages are raw bytes (challenge/response/welcome)
- RPC messages are pickle-serialized Python dicts

## Request: `{"get": "interface_stats"}`
- Pickle protocol: 2
- Pickle bytes: 39
- Opcodes: see control.log for full disassembly

## Response
- Type: dict
- Pickle bytes: 446
- Keys: ['interfaces', 'rxb', 'txb', 'rxs', 'txs', 'rss']
