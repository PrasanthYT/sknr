# Sknr dashboard

Next.js + shadcn/ui dashboard for the Sknr Rust API.

## Development

Run the backend API from the repository root:

```bash
cargo run -p sknr -- dashboard fixtures/demo-monorepo
```

Run the dashboard from `web/dashboard`:

```bash
pnpm dev
```

The frontend uses `NEXT_PUBLIC_SKNR_API_BASE`, defaulting to `http://127.0.0.1:4317`.
