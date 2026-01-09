# mobcrafter-api-worker

## D1 schema updates

This Worker uses a D1 binding named `SUBMISSIONS_DB` (see `wrangler.toml`).

### Create `comments` table (required for the comments feature)

Run one of the following (pick the one that matches your workflow):

- Apply via file:
	- Local (wrangler dev / local D1):
		- `wrangler d1 execute mobcrafter_portal --local --file ./migrations/0001_create_comments.sql`
	- Remote (production D1):
		- `wrangler d1 execute mobcrafter_portal --remote --file ./migrations/0001_create_comments.sql`

- Or paste/execute the SQL manually from `migrations/0001_create_comments.sql`.
