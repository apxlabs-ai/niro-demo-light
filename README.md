# niro-demo-light

A small FastAPI helpdesk service used as a niro pentest demo target. Two roles
(`customer`, `agent`), ticket CRUD, comments, JWT auth.

`main` is the clean baseline. The `demo/` directory replays a vulnerability-
introducing PR as a portable patch — `./demo/run.sh` applies it; `./demo/cleanup.sh`
closes the resulting open PRs.

## Run locally

```
./start.sh
```

Server starts on `http://127.0.0.1:8000` and prints `→ helpdesk ready on
http://127.0.0.1:8000` once `/health` responds. Interactive docs at `/docs`.
Stop with `./stop.sh`.

### Seeded users

| Email                 | Password              | Role     |
| --------------------- | --------------------- | -------- |
| `agent@helpdesk.test` | `agent-pass-1234`     | agent    |
| `alex@customer.test`  | `customer-pass-1234`  | customer |
| `blair@customer.test` | `customer-pass-1234`  | customer |

Log in with `POST /auth/login` (form fields `username`, `password`); attach
the returned JWT as `Authorization: Bearer <token>` on subsequent requests.

## Endpoints

| Method | Path                            | Auth     | Notes                                |
| ------ | ------------------------------- | -------- | ------------------------------------ |
| POST   | `/auth/signup`                  | —        | Creates a customer                   |
| POST   | `/auth/login`                   | —        | Returns JWT                          |
| GET    | `/me`                           | any user | Current user                         |
| POST   | `/tickets`                      | any user | Customer files a ticket              |
| GET    | `/tickets`                      | any user | Customers see own; agents see all    |
| GET    | `/tickets/{id}`                 | owner / agent |                                  |
| PATCH  | `/tickets/{id}`                 | agent    | Set status/priority/assignee         |
| POST   | `/tickets/{id}/comments`        | owner / agent |                                  |
| GET    | `/tickets/{id}/comments`        | owner / agent |                                  |
