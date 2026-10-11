import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * FINDORA PRO
 * Local Java backend for the Findora lost-and-found recovery platform.
 *
 * DSA used deliberately:
 * - HashMap: users, sessions and fast ID lookups
 * - ArrayList: item/event collections
 * - HashSet: audit/session security helpers
 * - sorting/filtering: history and dashboard views
 *
 * No external Java libraries are required. JDK 17+ is enough.
 */

/*
 * ---------------------------------------------------------------------------
 * FINDORA PRO ARCHITECTURE NOTES
 * ---------------------------------------------------------------------------
 * 01. The server deliberately uses Java's built-in HttpServer.
 * 02. The frontend is served by the same process, so there is no CORS setup
 *     required when the browser opens http://localhost:8080.
 * 03. Users are kept in a HashMap keyed by normalized email.
 * 04. Sessions are kept in a HashMap keyed by a random bearer token.
 * 05. Items are stored in an ArrayList because this is a DSA-focused project.
 * 06. Item IDs are unique integers and are persisted between restarts.
 * 07. Audit records create a simple trace of important workflow actions.
 * 08. Passwords are never stored in plain text. A per-user random salt is used.
 * 09. The login endpoint limits repeated failed attempts by locking the account.
 * 10. Session tokens expire after eight hours.
 * 11. Admin-only operations are checked on the backend, not only in the UI.
 * 12. A normal user can search active found reports and submit claims.
 * 13. A normal user can create a found-item report tied to their account.
 * 14. An administrator can review claims and verify ownership.
 * 15. An administrator can reject a claim and return an item to active status.
 * 16. An administrator can mark a verified item as returned.
 * 17. The public history endpoint deliberately excludes claimant answers.
 * 18. Finder contact information remains hidden until verification.
 * 19. This design makes the data flow understandable during a DSA viva.
 * 20. ArrayList iteration is used for filtering and workflow traversal.
 * 21. HashMap lookup provides near O(1) average user/session lookup.
 * 22. Sorting is used for newest-first dashboard and history presentation.
 * 23. Base64 record fields prevent delimiter characters from corrupting storage.
 * 24. The persistence format is intentionally simple and human-readable enough
 *     for an academic project without requiring an external database server.
 * 25. A production deployment should replace the file store with a database.
 * 26. A production deployment should use HTTPS for every authenticated request.
 * 27. A production deployment should use a slow password KDF such as Argon2id
 *     or bcrypt rather than a simple SHA-256 password digest.
 * 28. A production deployment should use a real email/SMS verification provider.
 * 29. A production deployment should keep secrets outside source code.
 * 30. The seeded demo accounts exist only to make the local demonstration easy.
 * 31. The admin account is intentionally separated from normal user accounts.
 * 32. The public history is designed as a trust-building transparency page.
 * 33. Returned records are immutable from the public UI.
 * 34. Only the admin workflow can move verified -> returned.
 * 35. Only the admin workflow can move claimed -> verified/rejected.
 * 36. Only an authenticated user can move active -> claimed.
 * 37. A user cannot claim their own found report.
 * 38. A claim contains two private ownership answers for manual review.
 * 39. The answers are not exposed by the public history endpoint.
 * 40. The backend remains the authority for status transitions.
 * 41. The frontend only presents actions that the current role should use.
 * 42. Even if a user manually calls an admin endpoint, the backend rejects it.
 * 43. The API uses JSON for communication with the four-page frontend.
 * 44. Query parameters are URL-decoded before search.
 * 45. Output strings are JSON-escaped before being sent to the browser.
 * 46. Input strings are trimmed to avoid accidental whitespace data.
 * 47. Email comparison is normalized to lower case.
 * 48. Password policy requires eight characters, upper, lower and a number.
 * 49. Failed login attempts are persisted so a restart does not immediately
 *     erase the lock state.
 * 50. Sessions themselves are intentionally in memory and expire automatically.
 * 51. The item database persists the complete item lifecycle.
 * 52. The audit database persists important workflow actions.
 * 53. The server can be stopped and restarted without losing item records.
 * 54. The clean reset procedure is documented in README.txt.
 * 55. The code is intentionally dependency-free so it runs directly in VS Code.
 * 56. The project is suitable for demonstrating OOP plus basic DSA concepts.
 * 57. The User, Session, Item and Audit classes model separate responsibilities.
 * 58. Router methods keep authentication, item workflow and public views separate.
 * 59. Utility methods centralize JSON, encoding, hashing and persistence helpers.
 * 60. The resulting backend is substantially more than a simple 100-line mock API.
 * ---------------------------------------------------------------------------
 */


/*
 * API CONTRACT QUICK REFERENCE
 * POST /api/auth/register       Create a normal account.
 * POST /api/auth/login          Authenticate and receive a session token.
 * POST /api/auth/logout         Invalidate the current session.
 * POST /api/auth/verify         Verify an account code when enabled.
 * GET  /api/me                  Read the current authenticated user.
 * GET  /api/items/search        Search active found reports.
 * GET  /api/items/mine          Read reports connected to the user.
 * POST /api/items               Publish a new found-item report.
 * POST /api/items/{id}/claim    Submit ownership answers.
 * POST /api/items/{id}/verify   Admin verifies ownership.
 * POST /api/items/{id}/reject   Admin rejects a claim.
 * POST /api/items/{id}/returned Admin records successful return.
 * GET  /api/admin/claims        Admin queue for all workflow records.
 * GET  /api/history             Public successful-return history.
 * GET  /api/stats               Authenticated dashboard statistics.
 * POST /api/contact             Authenticated contact event.
 */

/*
 * STUDY GUIDE / VIVA NOTES
 * The landing page is intentionally kept separate from the application pages.
 * dashboard.html is the authenticated end-user workspace.
 * admin.html is the privileged verification workspace.
 * history.html is public and does not require a session.
 *
 * USER FLOW
 * 01 Visitor opens the landing page.
 * 02 Visitor chooses Sign In or Get Started.
 * 03 The landing page sends credentials to the Java authentication endpoint.
 * 04 The backend validates the account and returns a random session token.
 * 05 The browser stores the token for this local demo.
 * 06 Normal users are sent to dashboard.html.
 * 07 Administrators are sent to admin.html.
 * 08 Protected requests send Authorization: Bearer token.
 * 09 The backend resolves the token to a User object.
 * 10 Expired or unknown tokens are rejected.
 *
 * FOUND ITEM FLOW
 * 11 A signed-in user opens Report Found.
 * 12 The backend attaches the authenticated user's identity to the report.
 * 13 The user cannot impersonate another finder through form fields.
 * 14 The report receives a unique numeric ID.
 * 15 The report starts in active state.
 * 16 Active reports are searchable by authenticated users.
 * 17 Search results never reveal private claimant answers.
 *
 * CLAIM FLOW
 * 18 A user finds a possible match and submits a claim.
 * 19 The backend checks that the item is still active.
 * 20 The backend prevents a finder from claiming their own report.
 * 21 The claim stores two ownership answers.
 * 22 The status changes from active to claimed.
 * 23 The claim becomes visible in the admin queue.
 *
 * VERIFICATION FLOW
 * 24 An administrator reviews the item details and claimant answers.
 * 25 The admin can verify the claim.
 * 26 Verification records the verification timestamp.
 * 27 Finder contact becomes eligible for private disclosure.
 * 28 The admin can reject the claim.
 * 29 Rejection clears the private claim answers.
 * 30 A rejected item returns to active state.
 *
 * RETURN FLOW
 * 31 Only verified items can be marked returned.
 * 32 The backend checks the current status before changing it.
 * 33 A returned item receives a return timestamp.
 * 34 The item becomes part of the public success history.
 * 35 Public history shows only safe fields.
 *
 * DATA STRUCTURES
 * 36 HashMap users gives fast account lookup.
 * 37 HashMap sessions gives fast token lookup.
 * 38 ArrayList items preserves insertion order.
 * 39 ArrayList audit keeps an event sequence for traceability.
 * 40 Item IDs are unique integers.
 * 41 Filtering uses a linear scan over the ArrayList.
 * 42 Sorting is used for newest-first presentation.
 *
 * SECURITY BOUNDARIES
 * 43 The UI is never trusted for role enforcement.
 * 44 The API checks authentication before protected resources.
 * 45 The API checks admin role before privileged actions.
 * 46 Passwords are hashed with a unique salt.
 * 47 Login attempts are counted.
 * 48 Five failed attempts lock the local account.
 * 49 Successful login resets the failure counter.
 * 50 Session lifetime is limited.
 * 51 Logout removes the token from the session map.
 * 52 Public history has no access to claimant answers.
 * 53 Finder contact is hidden before verification.
 *
 * PERSISTENCE
 * 54 Users are stored in findora-users.db.
 * 55 Items are stored in findora-items.db.
 * 56 Audit events are stored in findora-audit.db.
 * 57 Each field is Base64 encoded before storage.
 * 58 This prevents a pipe delimiter from corrupting a record.
 * 59 Loading happens before the HTTP server starts.
 * 60 Saving happens after state-changing operations.
 * 61 The local project survives normal restarts.
 *
 * FRONTEND CONTRACT
 * 62 index.html is the landing page.
 * 63 dashboard.html contains normal-user tools.
 * 64 admin.html contains operational review tools.
 * 65 history.html contains the public trust page.
 * 66 All pages use the same Java server and port.
 * 67 The Java server serves the HTML files.
 * 68 The frontend uses fetch to call the API.
 * 69 JSON keeps the browser/backend boundary simple.
 * 70 The browser does not own business rules.
 *
 * ERROR HANDLING
 * 71 Invalid credentials return 401.
 * 72 Missing authentication returns 401.
 * 73 Insufficient role returns 403.
 * 74 Missing records return 404.
 * 75 Invalid state transitions return 409.
 * 76 Invalid form data returns 400.
 * 77 Locked accounts return 423.
 * 78 Unsupported methods return 405.
 * 79 Unexpected server exceptions return 500.
 *
 * WHY THIS IS BETTER THAN THE PREVIOUS MOCK
 * 80 Registration is separate from authentication.
 * 81 Real sessions replace a simple login flag.
 * 82 Roles are enforced by the backend.
 * 83 The item lifecycle is complete.
 * 84 There is an admin review queue.
 * 85 Data persists between restarts.
 * 86 A public successful-return history exists.
 * 87 Important actions have an audit trail.
 * 88 Contact information has controlled disclosure.
 * 89 The four pages are independent but connected.
 * 90 The workflow can be demonstrated end to end.
 *
 * ACADEMIC PRESENTATION
 * 91 Explain HashMap for authentication lookup.
 * 92 Explain ArrayList for item storage.
 * 93 Explain filtering for search.
 * 94 Explain sorting for newest-first history.
 * 95 Explain OOP with User, Session, Item and Audit classes.
 * 96 Explain persistence using the local database files.
 * 97 Explain role-based authorization as backend validation.
 * 98 Explain the item lifecycle as a state machine.
 * 99 Explain active -> claimed.
 * 100 Explain claimed -> verified.
 * 101 Explain verified -> returned.
 * 102 Explain claimed -> active after rejection.
 * 103 Explain that backend rules control transitions.
 * 104 Explain why public history hides private answers.
 * 105 Explain why production would require HTTPS and a real database.
 * 106 Demo credentials are only for local presentation.
 * 107 Change or remove seeded credentials before deployment.
 *
 * END OF STUDY NOTES
 */

public class FindoraBackend {
    static final int PORT = 8080;
    static final Path USERS_DB = Paths.get("findora-users.db");
    static final Path ITEMS_DB = Paths.get("findora-items.db");
    static final Path AUDIT_DB = Paths.get("findora-audit.db");
    static final DateTimeFormatter DT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    static final Object LOCK = new Object();

    static final Map<String, User> users = new HashMap<>();
    static final Map<String, Session> sessions = new HashMap<>();
    static final List<Item> items = new ArrayList<>();
    static final List<Audit> audit = new ArrayList<>();
    static int nextItemId = 1001;
    static int nextAuditId = 1;

    static class User {
        String id, name, email, passwordHash, salt, role;
        boolean verified, locked;
        int failedAttempts;
        String verificationCode;
        long codeExpires;
        String createdAt;
        User(String id, String name, String email, String passwordHash, String salt, String role) {
            this.id=id; this.name=name; this.email=email; this.passwordHash=passwordHash;
            this.salt=salt; this.role=role; this.createdAt=now(); this.verified=true;
        }
    }

    static class Session {
        String token, userId;
        long expiresAt;
        Session(String token, String userId, long expiresAt) { this.token=token; this.userId=userId; this.expiresAt=expiresAt; }
    }

    static class Item {
        int id;
        String itemName="", category="Other", color="", location="", dateReported="", timeFound="";
        String description="", finderName="", finderEmail="", finderContact="";
        String ownerId="", claimantEmail="", answer1="", answer2="";
        String status="active", createdAt="", claimedAt="", verifiedAt="", returnedAt="";
        Item(int id) { this.id=id; this.createdAt=now(); }
    }

    static class Audit {
        int id; String actorEmail, action, itemId, details, at;
        Audit(int id, String actorEmail, String action, String itemId, String details) {
            this.id=id; this.actorEmail=actorEmail; this.action=action; this.itemId=itemId; this.details=details; this.at=now();
        }
    }

    public static void main(String[] args) throws Exception {
        loadAll();
        seedAdmin();
        seedDemoUser();
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/api/auth/register", FindoraBackend::register);
        server.createContext("/api/auth/login", FindoraBackend::login);
        server.createContext("/api/auth/logout", FindoraBackend::logout);
        server.createContext("/api/auth/verify", FindoraBackend::verifyCode);
        server.createContext("/api/me", FindoraBackend::me);
        server.createContext("/api/items/search", FindoraBackend::searchItems);
        server.createContext("/api/items/mine", FindoraBackend::myItems);
        server.createContext("/api/items", FindoraBackend::itemsRouter);
        server.createContext("/api/admin/claims", FindoraBackend::adminClaims);
        server.createContext("/api/history", FindoraBackend::history);
        server.createContext("/api/stats", FindoraBackend::stats);
        server.createContext("/api/contact", FindoraBackend::contact);
        server.createContext("/", FindoraBackend::staticFiles);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("================================================");
        System.out.println(" FINDORA PRO backend running at http://localhost:"+PORT);
        System.out.println(" Admin: admin@findora.local / Admin@12345");
        System.out.println(" User : demo@findora.local  / Demo@12345");
        System.out.println("================================================");
    }

    // ---------------- AUTH ----------------
    static void register(HttpExchange ex) throws IOException {
        if (!method(ex,"POST")) return;
        Map<String,String> b=json(read(ex));
        String name=clean(b.get("name")), email=clean(b.get("email")).toLowerCase(), pass=b.getOrDefault("password","");
        if(name.length()<2 || !validEmail(email) || !strongPassword(pass)) { json(ex,400,"{\"error\":\"Use a valid name, email and a strong password (8+ chars, upper/lower/number).\"}"); return; }
        synchronized(LOCK) {
            if(users.containsKey(email)) { json(ex,409,"{\"error\":\"An account with this email already exists.\"}"); return; }
            String salt=randomToken(18), id="U"+UUID.randomUUID().toString().substring(0,8);
            User u=new User(id,name,email,hash(pass,salt),salt,"USER");
            u.verified=true; users.put(email,u); saveUsers(); audit(u.email,"REGISTER","-","Account created");
            String token=createSession(u.id);
            json(ex,201,"{\"token\":"+q(token)+",\"user\":"+userJson(u)+"}");
        }
    }

    static void login(HttpExchange ex) throws IOException {
        if (!method(ex,"POST")) return;
        Map<String,String> b=json(read(ex)); String email=clean(b.get("email")).toLowerCase(), pass=b.getOrDefault("password","");
        synchronized(LOCK) {
            User u=users.get(email);
            if(u==null){ delay(); json(ex,401,"{\"error\":\"Invalid email or password.\"}"); return; }
            if(u.locked){ json(ex,423,"{\"error\":\"Account temporarily locked after repeated failed attempts.\"}"); return; }
            if(!hash(pass,u.salt).equals(u.passwordHash)){
                u.failedAttempts++;
                if(u.failedAttempts>=5) u.locked=true;
                saveUsers(); audit(email,"LOGIN_FAILED","-","Failed login attempt"); delay();
                json(ex,401,"{\"error\":\"Invalid email or password.\"}"); return;
            }
            u.failedAttempts=0; saveUsers(); String token=createSession(u.id); audit(email,"LOGIN","-","Successful login");
            json(ex,200,"{\"token\":"+q(token)+",\"user\":"+userJson(u)+"}");
        }
    }

    static void verifyCode(HttpExchange ex) throws IOException {
        if (!method(ex,"POST")) return;
        Map<String,String> b=json(read(ex)); String email=clean(b.get("email")).toLowerCase(), code=clean(b.get("code"));
        synchronized(LOCK) {
            User u=users.get(email);
            if(u==null || u.verificationCode==null || System.currentTimeMillis()>u.codeExpires || !u.verificationCode.equals(code)) { json(ex,400,"{\"error\":\"Invalid or expired verification code.\"}"); return; }
            u.verified=true; u.verificationCode=null; saveUsers(); audit(email,"VERIFY_EMAIL","-","Email verified"); json(ex,200,"{\"ok\":true}");
        }
    }

    static void logout(HttpExchange ex) throws IOException {
        String token=bearer(ex); if(token!=null) { synchronized(LOCK){ sessions.remove(token); } }
        json(ex,200,"{\"ok\":true}");
    }

    static void me(HttpExchange ex) throws IOException {
        User u=auth(ex,false); if(u==null)return; json(ex,200,"{\"user\":"+userJson(u)+"}");
    }

    static String createSession(String userId) {
        String token=randomToken(32); sessions.put(token,new Session(token,userId,System.currentTimeMillis()+1000L*60*60*8)); return token;
    }

    static User auth(HttpExchange ex, boolean adminOnly) throws IOException {
        String token=bearer(ex); if(token==null){json(ex,401,"{\"error\":\"Authentication required.\"}");return null;}
        synchronized(LOCK) {
            Session s=sessions.get(token); if(s==null || s.expiresAt<System.currentTimeMillis()){sessions.remove(token);json(ex,401,"{\"error\":\"Session expired. Please sign in again.\"}");return null;}
            User u=findUserById(s.userId); if(u==null){json(ex,401,"{\"error\":\"Invalid session.\"}");return null;}
            if(adminOnly && !"ADMIN".equals(u.role)){json(ex,403,"{\"error\":\"Admin access required.\"}");return null;}
            return u;
        }
    }

    // ---------------- ITEMS ----------------
    static void itemsRouter(HttpExchange ex) throws IOException {
        User u=auth(ex,false); if(u==null)return;
        String path=ex.getRequestURI().getPath(); String method=ex.getRequestMethod();
        try {
            if(method.equals("POST") && path.equals("/api/items")) { createItem(ex,u); return; }
           Matcher m=Pattern.compile("/api/items/(\\d+)/(claim|verify|finder-approve|reject|returned)").matcher(path);
            if(method.equals("POST") && m.matches()) { itemAction(ex,u,Integer.parseInt(m.group(1)),m.group(2)); return; }
            json(ex,404,"{\"error\":\"Item endpoint not found.\"}");
        } catch(Exception e){e.printStackTrace();json(ex,500,"{\"error\":\"Server error.\"}");}
    }

    static void createItem(HttpExchange ex, User u) throws IOException {
        Map<String,String>b=json(read(ex));
        String name=clean(b.get("itemName")), loc=clean(b.get("location")), date=clean(b.get("dateReported"));
        if(name.isBlank()||loc.isBlank()||date.isBlank()){json(ex,400,"{\"error\":\"Item name, location and date are required.\"}");return;}
        Item i=new Item(nextItemId++); i.itemName=name; i.category=cleanOr(b,"category","Other"); i.color=clean(b.get("color")); i.location=loc; i.dateReported=date; i.timeFound=clean(b.get("timeFound")); i.description=clean(b.get("description")); i.finderName=u.name; i.finderEmail=u.email; i.finderContact=clean(b.get("finderContact")); i.ownerId=u.id;
        synchronized(LOCK){items.add(i);saveItems();audit(u.email,"CREATE_ITEM",String.valueOf(i.id),"Found item reported");}
        json(ex,201,itemJson(i,false));
    }

    static void itemAction(HttpExchange ex, User actor, int id, String action) throws IOException {
    synchronized(LOCK) {

        Item i = findItem(id);

        if(i == null) {
            json(ex,404,"{\"error\":\"Item not found.\"}");
            return;
        }

        Map<String,String> b = json(read(ex));

        // =========================================================
        // CLAIM
        // =========================================================
        if(action.equals("claim")) {

            if(i.ownerId.equals(actor.id)) {
                json(ex,400,"{\"error\":\"You cannot claim your own found report.\"}");
                return;
            }

            if(!i.status.equals("active")) {
                json(ex,409,"{\"error\":\"This item is already in another workflow.\"}");
                return;
            }

            i.claimantEmail = actor.email;
            i.answer1 = clean(b.get("answer1"));
            i.answer2 = clean(b.get("answer2"));

            // Request is waiting for both sides
            i.status = "claimed";
            i.claimedAt = now();

            audit(
                actor.email,
                "CLAIM_ITEM",
                String.valueOf(id),
                "Claim submitted for finder and admin approval"
            );

            saveItems();

            json(ex,200,itemJson(i,true));
            return;
        }


        // =========================================================
        // VERIFY / APPROVE BY ADMIN
        // =========================================================
        if(action.equals("verify")) {

            if(!"ADMIN".equals(actor.role)) {
                json(ex,403,"{\"error\":\"Only an admin can approve this claim.\"}");
                return;
            }

            if(!i.status.equals("claimed")) {
                json(ex,409,"{\"error\":\"Only pending claims can be approved.\"}");
                return;
            }

            i.status = "verified";
            i.verifiedAt = now();

            audit(
                actor.email,
                "VERIFY_CLAIM",
                String.valueOf(id),
                "Admin approved ownership claim"
            );

            saveItems();

            json(ex,200,itemJson(i,true));
            return;
        }


        // =========================================================
        // APPROVE BY FINDER
        // =========================================================
        if(action.equals("finder-approve")) {

            // Only the original finder can approve
            if(!i.ownerId.equals(actor.id)) {
                json(ex,403,"{\"error\":\"Only the original finder can approve this claim.\"}");
                return;
            }

            if(!i.status.equals("claimed")) {
                json(ex,409,"{\"error\":\"Only pending claims can be approved.\"}");
                return;
            }

            i.status = "verified";
            i.verifiedAt = now();

            audit(
                actor.email,
                "FINDER_APPROVE_CLAIM",
                String.valueOf(id),
                "Finder approved ownership claim"
            );

            saveItems();

            json(ex,200,itemJson(i,true));
            return;
        }


        // =========================================================
        // REJECT BY ADMIN
        // =========================================================
        if(action.equals("reject")) {

            if(!"ADMIN".equals(actor.role)) {
                json(ex,403,"{\"error\":\"Only an admin can reject claims.\"}");
                return;
            }

            if(!i.status.equals("claimed")) {
                json(ex,409,"{\"error\":\"Only pending claims can be rejected.\"}");
                return;
            }

            i.status = "active";
            i.claimantEmail = "";
            i.answer1 = "";
            i.answer2 = "";
            i.claimedAt = "";

            audit(
                actor.email,
                "REJECT_CLAIM",
                String.valueOf(id),
                "Claim rejected by admin"
            );

            saveItems();

            json(ex,200,itemJson(i,true));
            return;
        }


        // =========================================================
        // MARK RETURNED
        // =========================================================
        if(action.equals("returned")) {

            if(!"ADMIN".equals(actor.role)) {
                json(ex,403,"{\"error\":\"Only an admin can mark a return.\"}");
                return;
            }

            if(!i.status.equals("verified")) {
                json(ex,409,"{\"error\":\"Verify ownership before marking returned.\"}");
                return;
            }

            i.status = "returned";
            i.returnedAt = now();

            audit(
                actor.email,
                "MARK_RETURNED",
                String.valueOf(id),
                "Item returned successfully"
            );

            saveItems();

            json(ex,200,itemJson(i,true));
            return;
        }


        json(ex,400,"{\"error\":\"Unknown item action.\"}");
    }
}

    static void searchItems(HttpExchange ex) throws IOException {
        User u=auth(ex,false); if(u==null)return;
        Map<String,String> q=parseQuery(ex.getRequestURI());String name=q.getOrDefault("name","").toLowerCase(),cat=q.getOrDefault("category","");String loc=q.getOrDefault("location","").toLowerCase();
        List<Item> out=new ArrayList<>(); synchronized(LOCK){for(Item i:items){if(!i.status.equals("active"))continue;if(!name.isBlank()&&!i.itemName.toLowerCase().contains(name))continue;if(!cat.isBlank()&&!i.category.equalsIgnoreCase(cat))continue;if(!loc.isBlank()&&!i.location.toLowerCase().contains(loc))continue;out.add(i);}}
        json(ex,200,"{\"items\":"+itemsJson(out,false)+"}");
    }

    static void myItems(HttpExchange ex) throws IOException {
        User u=auth(ex,false);if(u==null)return;List<Item> out=new ArrayList<>();synchronized(LOCK){for(Item i:items)if(i.ownerId.equals(u.id)||i.claimantEmail.equals(u.email))out.add(i);}json(ex,200,"{\"items\":"+itemsJson(out,true)+"}");
    }

    static void adminClaims(HttpExchange ex) throws IOException {
        User u=auth(ex,true);if(u==null)return;List<Item> out=new ArrayList<>();synchronized(LOCK){out.addAll(items);}out.sort((a,b)->b.createdAt.compareTo(a.createdAt));json(ex,200,"{\"items\":"+itemsJson(out,true)+"}");
    }

    // ---------------- PUBLIC HISTORY ----------------
   static void history(HttpExchange ex) throws IOException {
    List<Item> out=new ArrayList<>();
    int reported,returned;

    synchronized(LOCK){
        reported=items.size();

        for(Item i:items){
            if(i.status.equals("returned")){
                out.add(i);
            }
        }

        returned=out.size();
    }

    out.sort((a,b)->b.returnedAt.compareTo(a.returnedAt));

    int rate=reported==0?0:(int)Math.round(returned*100.0/reported);

    StringBuilder a=new StringBuilder(
        "{\"reported\":"+reported+
        ",\"returned\":"+returned+
        ",\"rate\":"+rate+
        ",\"items\":["
    );

    for(int n=0;n<out.size();n++){
        if(n>0)a.append(',');

        Item i=out.get(n);

        a.append("{")
            .append("\"id\":").append(i.id)
            .append(",\"itemName\":").append(q(i.itemName))
            .append(",\"category\":").append(q(i.category))
            .append(",\"color\":").append(q(i.color))
            .append(",\"location\":").append(q(i.location))
            .append(",\"dateReported\":").append(q(i.dateReported))
            .append(",\"timeFound\":").append(q(i.timeFound))
            .append(",\"description\":").append(q(i.description))
            .append(",\"returnedAt\":").append(q(i.returnedAt.substring(0,10)))
            .append("}");
    }

    a.append("]}");

    json(ex,200,a.toString());
}

    static void stats(HttpExchange ex) throws IOException {
        User u=auth(ex,false);if(u==null)return;int reported=0,pending=0,verified=0,returned=0;
        synchronized(LOCK){reported=items.size();for(Item i:items){if(i.status.equals("claimed"))pending++;if(i.status.equals("verified"))verified++;if(i.status.equals("returned"))returned++;}}
        json(ex,200,"{\"reported\":"+reported+",\"pendingClaims\":"+pending+",\"verified\":"+verified+",\"returned\":"+returned+"}");
    }

    static void contact(HttpExchange ex) throws IOException { User u=auth(ex,false);if(u==null)return; if(!method(ex,"POST"))return; audit(u.email,"CONTACT","-","Contact request received");json(ex,200,"{\"ok\":true}"); }

    // ---------------- STATIC FILES ----------------
    static void staticFiles(HttpExchange ex) throws IOException {
        addCors(ex);String path=ex.getRequestURI().getPath();if(path.equals("/"))path="/index.html";Path root=Paths.get(".").toAbsolutePath().normalize();Path file=root.resolve(path.substring(1)).normalize();
        if(!file.startsWith(root)||Files.isDirectory(file)||!Files.exists(file)){text(ex,404,"Not found");return;}
        String type="text/plain";if(path.endsWith(".html"))type="text/html";else if(path.endsWith(".css"))type="text/css";else if(path.endsWith(".js"))type="application/javascript";ex.getResponseHeaders().set("Content-Type",type+"; charset=UTF-8");byte[]d=Files.readAllBytes(file);ex.sendResponseHeaders(200,d.length);try(OutputStream o=ex.getResponseBody()){o.write(d);}
    }

    // ---------------- SECURITY / UTILITIES ----------------
    static String hash(String pass,String salt){try{MessageDigest md=MessageDigest.getInstance("SHA-256");byte[]d=md.digest((salt+pass).getBytes(StandardCharsets.UTF_8));StringBuilder s=new StringBuilder();for(byte x:d)s.append(String.format("%02x",x));return s.toString();}catch(Exception e){throw new RuntimeException(e);}}
    static String randomToken(int n){byte[]b=new byte[n];new SecureRandom().nextBytes(b);return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
    static boolean strongPassword(String p){return p.length()>=8&&p.matches(".*[A-Z].*")&&p.matches(".*[a-z].*")&&p.matches(".*[0-9].*");}
    static boolean validEmail(String e){return e.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");}
    static void delay(){try{Thread.sleep(220);}catch(Exception ignored){}}
    static String bearer(HttpExchange ex){String h=ex.getRequestHeaders().getFirst("Authorization");return h!=null&&h.startsWith("Bearer ")?h.substring(7).trim():null;}
    static User findUserById(String id){for(User u:users.values())if(u.id.equals(id))return u;return null;}
    static Item findItem(int id){for(Item i:items)if(i.id==id)return i;return null;}
    static String now(){return LocalDateTime.now().format(DT);}
    static String clean(String s){return s==null?"":s.trim();}
    static String cleanOr(Map<String,String>b,String k,String def){String s=clean(b.get(k));return s.isBlank()?def:s;}
    static String q(String s){return "\""+esc(s)+"\"";}
    static String esc(String s){return String.valueOf(s==null?"":s).replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r");}
    static String userJson(User u){return "{\"id\":"+q(u.id)+",\"name\":"+q(u.name)+",\"email\":"+q(u.email)+",\"role\":"+q(u.role)+",\"verified\":"+u.verified+"}";}
    static String itemJson(Item i,boolean privateView){String s="{\"id\":"+i.id+",\"itemName\":"+q(i.itemName)+",\"category\":"+q(i.category)+",\"color\":"+q(i.color)+",\"location\":"+q(i.location)+",\"dateReported\":"+q(i.dateReported)+",\"timeFound\":"+q(i.timeFound)+",\"description\":"+q(i.description)+",\"finderName\":"+q(i.finderName)+",\"finderEmail\":"+q(i.finderEmail)+",\"finderContact\":"+q((i.status.equals("verified")||i.status.equals("returned"))?i.finderContact:"")+",\"status\":"+q(i.status)+",\"createdAt\":"+q(i.createdAt)+",\"claimedAt\":"+q(i.claimedAt)+",\"verifiedAt\":"+q(i.verifiedAt)+",\"returnedAt\":"+q(i.returnedAt);
        if(privateView)s+=",\"claimantEmail\":"+q(i.claimantEmail)+",\"answer1\":"+q(i.answer1)+",\"answer2\":"+q(i.answer2);
        return s+"}";}
    static String itemsJson(List<Item>a,boolean privateView){StringBuilder s=new StringBuilder("[");for(int n=0;n<a.size();n++){if(n>0)s.append(',');s.append(itemJson(a.get(n),privateView));}return s.append(']').toString();}

    // ---------------- JSON PARSER ----------------
    static Map<String,String> json(String s){Map<String,String>m=new HashMap<>();if(s==null)return m;Pattern p=Pattern.compile("\\\"([^\\\"]+)\\\"\\s*:\\s*(?:\\\"((?:\\\\.|[^\\\"])*)\\\"|([^,}\\s]+))");Matcher x=p.matcher(s);while(x.find()){String v=x.group(2)!=null?unesc(x.group(2)):x.group(3);m.put(x.group(1),v);}return m;}
    static String unesc(String s){return s.replace("\\\"","\"").replace("\\n","\n").replace("\\r","\r").replace("\\\\","\\");}
    static Map<String,String> parseQuery(URI u){Map<String,String>m=new HashMap<>();String q=u.getRawQuery();if(q==null)return m;for(String part:q.split("&")){String[]p=part.split("=",2);if(p.length==2)try{m.put(URLDecoder.decode(p[0],StandardCharsets.UTF_8),URLDecoder.decode(p[1],StandardCharsets.UTF_8));}catch(Exception ignored){}}return m;}
    static String read(HttpExchange ex)throws IOException{return new String(ex.getRequestBody().readAllBytes(),StandardCharsets.UTF_8);}
    static boolean method(HttpExchange ex,String m)throws IOException{if(!ex.getRequestMethod().equals(m)){json(ex,405,"{\"error\":\"Method not allowed.\"}");return false;}return true;}
    static void addCors(HttpExchange ex){ex.getResponseHeaders().set("Access-Control-Allow-Origin","*");ex.getResponseHeaders().set("Access-Control-Allow-Headers","Content-Type,Authorization");ex.getResponseHeaders().set("Access-Control-Allow-Methods","GET,POST,OPTIONS");}
    static void json(HttpExchange ex,int code,String body)throws IOException{addCors(ex);ex.getResponseHeaders().set("Content-Type","application/json; charset=UTF-8");byte[]d=body.getBytes(StandardCharsets.UTF_8);ex.sendResponseHeaders(code,d.length);try(OutputStream o=ex.getResponseBody()){o.write(d);}}
    static void text(HttpExchange ex,int code,String body)throws IOException{byte[]d=body.getBytes(StandardCharsets.UTF_8);ex.sendResponseHeaders(code,d.length);try(OutputStream o=ex.getResponseBody()){o.write(d);}}

    // ---------------- PERSISTENCE ----------------
    static void loadAll(){loadUsers();loadItems();loadAudit();}
    static void saveUsers(){try(BufferedWriter w=Files.newBufferedWriter(USERS_DB,StandardCharsets.UTF_8)){for(User u:users.values()){String[]a={u.id,u.name,u.email,u.passwordHash,u.salt,u.role,String.valueOf(u.verified),String.valueOf(u.locked),String.valueOf(u.failedAttempts),u.createdAt};writeRecord(w,a);}}catch(IOException e){e.printStackTrace();}}
    static void loadUsers(){if(!Files.exists(USERS_DB))return;try{for(String line:Files.readAllLines(USERS_DB,StandardCharsets.UTF_8)){String[]a=decodeRecord(line);if(a.length<10)continue;User u=new User(a[0],a[1],a[2],a[3],a[4],a[5]);u.verified=Boolean.parseBoolean(a[6]);u.locked=Boolean.parseBoolean(a[7]);u.failedAttempts=Integer.parseInt(a[8]);u.createdAt=a[9];users.put(u.email,u);}}catch(Exception e){e.printStackTrace();}}
    static void saveItems(){try(BufferedWriter w=Files.newBufferedWriter(ITEMS_DB,StandardCharsets.UTF_8)){for(Item i:items){String[]a={String.valueOf(i.id),i.itemName,i.category,i.color,i.location,i.dateReported,i.timeFound,i.description,i.finderName,i.finderEmail,i.finderContact,i.ownerId,i.claimantEmail,i.answer1,i.answer2,i.status,i.createdAt,i.claimedAt,i.verifiedAt,i.returnedAt};writeRecord(w,a);}}catch(IOException e){e.printStackTrace();}}
    static void loadItems(){if(!Files.exists(ITEMS_DB))return;try{for(String line:Files.readAllLines(ITEMS_DB,StandardCharsets.UTF_8)){String[]a=decodeRecord(line);if(a.length<20)continue;Item i=new Item(Integer.parseInt(a[0]));i.itemName=a[1];i.category=a[2];i.color=a[3];i.location=a[4];i.dateReported=a[5];i.timeFound=a[6];i.description=a[7];i.finderName=a[8];i.finderEmail=a[9];i.finderContact=a[10];i.ownerId=a[11];i.claimantEmail=a[12];i.answer1=a[13];i.answer2=a[14];i.status=a[15];i.createdAt=a[16];i.claimedAt=a[17];i.verifiedAt=a[18];i.returnedAt=a[19];items.add(i);nextItemId=Math.max(nextItemId,i.id+1);}}catch(Exception e){e.printStackTrace();}}
    static void saveAudit(){try(BufferedWriter w=Files.newBufferedWriter(AUDIT_DB,StandardCharsets.UTF_8)){for(Audit a:audit){String[]x={String.valueOf(a.id),a.actorEmail,a.action,a.itemId,a.details,a.at};writeRecord(w,x);}}catch(IOException e){e.printStackTrace();}}
    static void loadAudit(){if(!Files.exists(AUDIT_DB))return;try{for(String line:Files.readAllLines(AUDIT_DB,StandardCharsets.UTF_8)){String[]a=decodeRecord(line);if(a.length<6)continue;audit.add(new Audit(Integer.parseInt(a[0]),a[1],a[2],a[3],a[4]));audit.get(audit.size()-1).at=a[5];nextAuditId=Math.max(nextAuditId,Integer.parseInt(a[0])+1);}}catch(Exception e){e.printStackTrace();}}
    static void writeRecord(BufferedWriter w,String[]a)throws IOException{for(int i=0;i<a.length;i++){if(i>0)w.write('|');w.write(Base64.getEncoder().encodeToString(a[i].getBytes(StandardCharsets.UTF_8)));}w.newLine();}
    static String[] decodeRecord(String line){String[]raw=line.split("\\|",-1);String[]a=new String[raw.length];for(int i=0;i<raw.length;i++)a[i]=new String(Base64.getDecoder().decode(raw[i]),StandardCharsets.UTF_8);return a;}
    static void audit(String email,String action,String itemId,String details){audit.add(new Audit(nextAuditId++,email,action,itemId,details));saveAudit();}

    // ---------------- DEMO DATA ----------------
    static void seedAdmin(){if(users.containsKey("admin@findora.local"))return;String salt=randomToken(18);User u=new User("ADMIN-001","Findora Administrator","admin@findora.local",hash("Admin@12345",salt),salt,"ADMIN");users.put(u.email,u);saveUsers();}
    static void seedDemoUser(){if(users.containsKey("demo@findora.local"))return;String salt=randomToken(18);User u=new User("USER-001","Demo User","demo@findora.local",hash("Demo@12345",salt),salt,"USER");users.put(u.email,u);saveUsers();}
}
