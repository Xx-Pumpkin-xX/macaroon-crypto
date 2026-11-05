# API spec

Owner: Part 3. Reviewed by Part 1. Due 6/11.

Token goes in a request header (name TBD). The file key K stays after `#` in the URL and is never sent.

| Method | Path | Permission needed | Request | Response | Errors |
|---|---|---|---|---|---|
| POST | /files | none (creates the file, returns a Full Control token) | | | |
| POST | /share | any valid token (can only narrow it) | | | |
| GET | /files/{id} | Read | | | |
| PUT | /files/{id} | Edit | | | |
| POST | /revoke | Full Control | | | |
| DELETE | /files/{id} | Full Control | | | |
