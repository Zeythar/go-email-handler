# Simple contact form backend

This is a tiny Go HTTP service that accepts POST requests at `/api/contact` and forwards the content as an email via SMTP. It's intended for local testing alongside the Svelte frontend.

Configuration

Create a `.env` (or set env vars) with the values shown in `.env.example`:

- SMTP_HOST
- SMTP_PORT
- SMTP_USER
- SMTP_PASS
- TO_EMAIL

Running locally

1. Build and run:

```pwsh
go run main.go
```

2. In another shell run the test client:

```pwsh
go run test_send.go
```

You can also POST from the browser or the Svelte app. For local development the server sets Access-Control-Allow-Origin: \*.

Notes

- The server accepts JSON and form-encoded requests.
- For Gmail you will likely need an App Password or a service like Mailgun/SendGrid with SMTP credentials.
- In production restrict CORS and consider queuing or a transactional email provider.
