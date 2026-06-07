# DVWA Web Application Security Lab

A hands-on lab using Damn Vulnerable Web Application (DVWA) in Docker to practice common web vulnerabilities.

---

## Setup

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Go to `http://localhost/setup.php`, click Create / Reset Database, log in with `admin` / `password`.

---

## Labs

### Brute Force
Tested login form with wrong passwords to trigger error. Noticed credentials exposed in the URL. Successfully guessed the correct password showing no lockout protection exists.

---

### Command Injection
Used the ping form to chain system commands with `&&`. Retrieved the full `/etc/passwd` file from the server.

```
127.0.0.1 && cat /etc/passwd
```

---

### SQL Injection
Injected SQL into the User ID field to dump all users and password hashes from the database.

```
' OR '1'='1
' UNION SELECT user, password FROM users #
```

---

## What I Learned
- How brute force attacks exploit weak passwords and no lockout policies
- How command injection lets attackers run system commands through a web form
- How SQL injection can expose an entire database including password hashes

---

## Author
Mofolorunsho Adeleke — github.com/Mo200909
