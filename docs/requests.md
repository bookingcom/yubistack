Useful SQL request to troubleshoot yubistack
============================================

When your backend is SQL you can use the following requests to get information
directly from the database.

From the yubiauth database:

```sql
-- retrieve information for a given user name
SELECT *
FROM users u, user_yubikeys uy, yubikeys y
WHERE uy.yubikey_id = y.id AND uy.user_id = u.id
AND u.name = "fbar";

-- retrieve information for a given yubikey
SELECT *
FROM users u, user_yubikeys uy, yubikeys y
WHERE uy.yubikey_id = y.id AND uy.user_id = u.id
AND prefix = "dteffujehknh";

```

From the ykval database:

```sql
select * from yubikeys where yk_publicname = "dteffujehknh";
```

