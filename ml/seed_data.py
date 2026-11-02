from __future__ import annotations

import csv
from pathlib import Path

INSECURE = [
    ("python", r'''
query = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(query)
'''),
    ("python", r'''
cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}")
'''),
    ("python", r'''
cursor.execute("DELETE FROM sessions WHERE user = '%s'" % username)
'''),
    ("python", r'''
query = "UPDATE users SET email = '{}' WHERE id = {}".format(email, uid)
db.execute(query)
'''),
    ("python", r'''
os.system("ping -c 1 " + host)
'''),
    ("python", r'''
subprocess.call("ls " + user_dir, shell=True)
'''),
    ("python", r'''
subprocess.Popen(f"convert {filename} out.png", shell=True)
'''),
    ("python", r'''
result = eval(request.args.get("expr"))
'''),
    ("python", r'''
exec(user_code)
'''),
    ("python", r'''
data = pickle.loads(request.data)
'''),
    ("python", r'''
config = yaml.load(open(path))
'''),
    ("python", r'''
password = "SuperSecret123!"
connect(user, password)
'''),
    ("python", r'''
API_KEY = "sk_live_51H8a9dKJ2l3k4j5h6g7f8d9s0a"
'''),
    ("python", r'''
SECRET_KEY = "d41d8cd98f00b204e9800998ecf8427e"
app.config["SECRET_KEY"] = SECRET_KEY
'''),
    ("python", r'''
h = hashlib.md5(password.encode()).hexdigest()
'''),
    ("python", r'''
digest = hashlib.sha1(data).hexdigest()
store_password_hash(user, digest)
'''),
    ("python", r'''
app.run(host="0.0.0.0", debug=True)
'''),
    ("python", r'''
response = requests.get(url, verify=False)
'''),
    ("python", r'''
token = str(random.randint(100000, 999999))
send_reset_email(user, token)
'''),
    ("python", r'''
with open("/var/data/" + request.args["file"]) as f:
    return f.read()
'''),
    ("python", r'''
return render_template_string("<h1>Hello " + name + "</h1>")
'''),
    ("python", r'''
cipher = AES.new(key, AES.MODE_ECB)
'''),
    ("python", r'''
tmp = tempfile.mktemp()
open(tmp, "w").write(data)
'''),
    ("python", r'''
os.chmod(path, 0o777)
'''),
    ("python", r'''
ctx = ssl._create_unverified_context()
'''),
    ("python", r'''
def login(user, password):
    if password == "admin123":
        return True
    return False
'''),
    ("python", r'''
session_id = "".join(random.choice(string.ascii_letters) for _ in range(16))
'''),
    # ---- JavaScript ----
    ("javascript", r'''
db.query("SELECT * FROM users WHERE id = " + req.params.id);
'''),
    ("javascript", r'''
db.query(`SELECT * FROM users WHERE email = '${email}'`);
'''),
    ("javascript", r'''
eval(req.body.code);
'''),
    ("javascript", r'''
document.getElementById("out").innerHTML = location.hash.substring(1);
'''),
    ("javascript", r'''
exec("convert " + req.query.file + " out.png");
'''),
    ("javascript", r'''
const token = Math.random().toString(36).slice(2);
'''),
    ("javascript", r'''
const password = "hunter2hunter2";
'''),
    ("javascript", r'''
app.use(cors({ origin: "*", credentials: true }));
'''),
    ("javascript", r'''
const hash = crypto.createHash("md5").update(pw).digest("hex");
'''),
    ("javascript", r'''
const run = new Function(userInput);
run();
'''),
    ("javascript", r'''
res.send("<p>Hello " + req.query.name + "</p>");
'''),
    ("javascript", r'''
const agent = new https.Agent({ rejectUnauthorized: false });
'''),
    # ---- C ----
    ("c", r'''
char buf[16];
strcpy(buf, argv[1]);
'''),
    ("c", r'''
char name[32];
gets(name);
'''),
    ("c", r'''
sprintf(buf, "Hello %s", user);
'''),
    ("c", r'''
printf(user_input);
'''),
    ("c", r'''
system(cmd);
'''),
    ("c", r'''
char buf[64];
scanf("%s", buf);
'''),
    ("c", r'''
strcat(dest, src);
'''),
    ("c", r'''
int *p = malloc(n * sizeof(int));
for (i = 0; i <= n; i++) p[i] = 0;
'''),
    ("c", r'''
free(ptr);
printf("%s", ptr);
'''),
    ("c", r'''
char *tmp = tmpnam(NULL);
FILE *f = fopen(tmp, "w");
'''),
    # ---- PHP ----
    ("php", r'''
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
'''),
    ("php", r'''
echo $_GET['name'];
'''),
    ("php", r'''
eval($_POST['code']);
'''),
    ("php", r'''
system("ping " . $_GET['host']);
'''),
    ("php", r'''
$obj = unserialize($_COOKIE['data']);
'''),
    ("php", r'''
include($_GET['page'] . ".php");
'''),
    ("php", r'''
$hash = md5($_POST['password']);
'''),
]

SECURE = [
    # ---- Python ----
    ("python", r'''
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
'''),
    ("python", r'''
cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
'''),
    ("python", r'''
cursor.execute("DELETE FROM sessions WHERE user = %s", (username,))
'''),
    ("python", r'''
query = "UPDATE users SET email = ? WHERE id = ?"
db.execute(query, (email, uid))
'''),
    ("python", r'''
subprocess.run(["ping", "-c", "1", host], check=True)
'''),
    ("python", r'''
subprocess.run(["ls", user_dir], capture_output=True)
'''),
    ("python", r'''
subprocess.run(["convert", filename, "out.png"], check=True, timeout=30)
'''),
    ("python", r'''
result = ast.literal_eval(expr)
'''),
    ("python", r'''
handlers = {"add": add, "sub": sub}
result = handlers[op](a, b)
'''),
    ("python", r'''
data = json.loads(request.data)
'''),
    ("python", r'''
config = yaml.safe_load(open(path))
'''),
    ("python", r'''
password = os.environ["DB_PASSWORD"]
connect(user, password)
'''),
    ("python", r'''
API_KEY = os.getenv("API_KEY")
'''),
    ("python", r'''
SECRET_KEY = os.environ["SECRET_KEY"]
app.config["SECRET_KEY"] = SECRET_KEY
'''),
    ("python", r'''
h = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
'''),
    ("python", r'''
digest = hashlib.sha256(data).hexdigest()
store_checksum(user, digest)
'''),
    ("python", r'''
app.run(host="127.0.0.1", debug=False)
'''),
    ("python", r'''
response = requests.get(url, timeout=10)
'''),
    ("python", r'''
token = secrets.token_urlsafe(32)
send_reset_email(user, token)
'''),
    ("python", r'''
safe_name = os.path.basename(name)
path = os.path.join(BASE_DIR, safe_name)
with open(path) as f:
    return f.read()
'''),
    ("python", r'''
return render_template("hello.html", name=name)
'''),
    ("python", r'''
cipher = AES.new(key, AES.MODE_GCM)
'''),
    ("python", r'''
with tempfile.NamedTemporaryFile(delete=False) as tmp:
    tmp.write(data)
'''),
    ("python", r'''
os.chmod(path, 0o600)
'''),
    ("python", r'''
ctx = ssl.create_default_context()
'''),
    ("python", r'''
def login(user, password):
    return hmac.compare_digest(hash_pw(password), stored_hash(user))
'''),
    ("python", r'''
session_id = secrets.token_hex(16)
'''),
    ("python", r'''
for item in items:
    total += item.price * item.qty
'''),
    ("python", r'''
def read_config(path):
    with open(path) as f:
        return json.load(f)
'''),
    ("python", r'''
logger.info("User %s logged in", user_id)
'''),
    ("python", r'''
class User:
    def __init__(self, name):
        self.name = name
'''),
    ("python", r'''
def average(values):
    return sum(values) / len(values) if values else 0
'''),
    ("python", r'''
names = sorted(user.name for user in users if user.active)
'''),
    # ---- JavaScript ----
    ("javascript", r'''
db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
'''),
    ("javascript", r'''
db.query("SELECT * FROM users WHERE email = $1", [email]);
'''),
    ("javascript", r'''
const value = JSON.parse(req.body.payload);
'''),
    ("javascript", r'''
document.getElementById("out").textContent = location.hash.substring(1);
'''),
    ("javascript", r'''
execFile("convert", [file, "out.png"], callback);
'''),
    ("javascript", r'''
const token = crypto.randomBytes(32).toString("hex");
'''),
    ("javascript", r'''
const password = process.env.DB_PASSWORD;
'''),
    ("javascript", r'''
app.use(cors({ origin: "https://example.com" }));
'''),
    ("javascript", r'''
const hash = await bcrypt.hash(pw, 12);
'''),
    ("javascript", r'''
const total = items.reduce((sum, i) => sum + i.price, 0);
'''),
    ("javascript", r'''
function add(a, b) {
  return a + b;
}
'''),
    ("javascript", r'''
res.send(escapeHtml(req.query.name));
'''),
    ("javascript", r'''
const agent = new https.Agent({ rejectUnauthorized: true });
'''),
    # ---- C ----
    ("c", r'''
char buf[16];
strncpy(buf, argv[1], sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';
'''),
    ("c", r'''
char name[32];
fgets(name, sizeof(name), stdin);
'''),
    ("c", r'''
snprintf(buf, sizeof(buf), "Hello %s", user);
'''),
    ("c", r'''
printf("%s", user_input);
'''),
    ("c", r'''
if (execvp(prog, args) == -1) {
    perror("execvp");
}
'''),
    ("c", r'''
char buf[64];
scanf("%63s", buf);
'''),
    ("c", r'''
strncat(dest, src, sizeof(dest) - strlen(dest) - 1);
'''),
    ("c", r'''
int *p = malloc(n * sizeof(int));
if (p == NULL) return -1;
for (i = 0; i < n; i++) p[i] = 0;
'''),
    ("c", r'''
free(ptr);
ptr = NULL;
'''),
    ("c", r'''
int add(int a, int b) {
    return a + b;
}
'''),
    ("c", r'''
char tmpl[] = "/tmp/appXXXXXX";
int fd = mkstemp(tmpl);
'''),
    # ---- PHP ----
    ("php", r'''
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
'''),
    ("php", r'''
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
'''),
    ("php", r'''
$data = json_decode($_POST['payload'], true);
'''),
    ("php", r'''
$host = filter_var($_GET['host'], FILTER_VALIDATE_IP);
'''),
    ("php", r'''
$obj = json_decode($_COOKIE['data'], true);
'''),
    ("php", r'''
$pages = ['home', 'about'];
if (in_array($page, $pages, true)) {
    include($page . ".php");
}
'''),
    ("php", r'''
$hash = password_hash($password, PASSWORD_DEFAULT);
'''),
]

SAMPLES = ([(lang, 1, code.strip("\n")) for lang, code in INSECURE]
           + [(lang, 0, code.strip("\n")) for lang, code in SECURE])


# Harmless identifiers that can be renamed without changing whether the code is secure.
# Names that carry meaning for the label (password, token, secret, key...) are left alone.
_RENAMES = {
    "name": ["username", "user_name", "full_name", "term", "title"],
    "username": ["login", "account_name", "uname"],
    "host": ["hostname", "target", "server", "address"],
    "filename": ["fname", "upload", "doc_name"],
    "path": ["file_path", "target_path", "location", "full_path"],
    "user": ["customer", "account", "member", "client"],
    "data": ["payload", "content", "body", "text"],
    "url": ["endpoint", "link", "target_url"],
    "email": ["mail", "user_email", "contact"],
    "cmd": ["command", "shell_cmd", "line"],
    "expr": ["formula", "expression", "calc"],
    "uid": ["user_id", "ident", "row_id"],
    "buf": ["buffer", "line_buf", "out"],
    "dest": ["target_buf", "result", "outbuf"],
    "src": ["source", "input_buf", "text_in"],
    "query": ["sql", "statement", "stmt"],
    "items": ["entries", "rows", "records"],
    "cursor": ["cur", "c", "db_cursor"],
}


def augment(variants: int = 4, seed: int = 7):
    """Return (code, label, group) rows: each seed snippet plus renamed copies.

    ``group`` is the index of the original snippet, so cross-validation can keep every
    copy of one snippet on the same side of the train/test split.
    """
    import random
    import re

    rng = random.Random(seed)
    rows = []
    for group, (_, label, code) in enumerate(SAMPLES):
        rows.append((code, label, group))
        present = [word for word in _RENAMES if re.search(rf"\b{word}\b", code)]
        for _ in range(variants if present else 0):
            mapping = {w: rng.choice(_RENAMES[w]) for w in present if rng.random() < 0.7}
            variant = code
            for old, new in mapping.items():
                variant = re.sub(rf"\b{old}\b", new, variant)
            if variant != code:
                rows.append((variant, label, group))
    return rows


def write_csv(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["language", "label", "code"])
        writer.writerows(SAMPLES)


if __name__ == "__main__":
    target = Path(__file__).with_name("data") / "seed_dataset.csv"
    write_csv(target)
    print(f"wrote {len(SAMPLES)} rows to {target}")
