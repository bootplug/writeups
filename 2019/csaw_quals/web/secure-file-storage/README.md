# Secure File Storage

**Category**: Web

**Points**: 300

#### Challenge description:
get the admin's files

HINT: The admin checks the site frequently!

http://web.chal.csaw.io:1001

---

## Writeup coming soon! (tm)

**summary**: Log in, use api to create symlink for path traversal, use symlink to read and edit your own php session file in `/tmp`, change own permissions to get access to file list api and admin page -> list all session files and find the one with username "admin" -> change admin's username in session file to xss payload -> get encryption secret from admin's local storage -> read flag file
-> decrypt flag.
