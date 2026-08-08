# Secure MCP Tunnel runtime

This runtime is the private installation path for ChatGPT. It keeps the MCP
server off the public internet and opens only outbound HTTPS connections via
OpenAI's `tunnel-client`.

1. Build `deploy/Dockerfile.secure-tunnel` for the target platform.
2. Copy `compose.example.yaml` to a private installation directory.
3. Put the restricted runtime key at `secrets/control-plane-api-key` with mode
   `0600`. Never commit or bake it into the image.
4. Set `CONTROL_PLANE_TUNNEL_ID`, an opaque `MCP_VAULT_ID`, and the exact image
   reference in a private `.env`.
5. Run `docker compose up -d --no-build`.

No host port is published. A local publisher imports a validated snapshot with
the fixed command below over SSH; `<device-id>` and `<vault-id>` are opaque
identifiers, and the snapshot JSON is supplied on stdin.

```sh
docker compose exec -T runtime node dist/cli.js private-import \
  --vault-id '<vault-id>' --device-id '<device-id>'
```

The server activates a complete generation atomically and retains the previous
generation for rollback. The import identity cannot authenticate to the public
signed publisher endpoint.
