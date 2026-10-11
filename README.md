# Findora-
Findora — A smart university lost and found management system.

FINDORA PRO — JAVA + HTML/CSS/JS

Pages:
1. index.html        Premium landing page (original visual retained)
2. dashboard.html    Authenticated user dashboard: lost search, found reports, activity
3. admin.html         Admin operations dashboard: claims, verification, returns
4. history.html       Public successful-return history

RUN:
1) Install JDK 17+ (JDK 21 recommended).
2) Open this folder in VS Code.
3) Open terminal in this folder.
4) javac FindoraBackend.java
5) java FindoraBackend
6) Open http://localhost:8080

DEMO ADMIN:
Email: admin@findora.local
Password: Admin@12345

DEMO USER:
Email: demo@findora.local
Password: Demo@12345

The backend creates findora-users.db, findora-items.db and findora-audit.db beside the Java file.
For a clean reset, stop the server and delete those three files.

IMPORTANT: This is a local academic/demo system. Passwords are salted+hashed, sessions are token-based, and admin routes are role-protected, but production deployment would still need HTTPS, a real database, real email/SMS verification and stronger secret management.
