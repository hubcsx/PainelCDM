#!/usr/bin/env python3
"""
Servidor proxy local para o Painel N2 CDM — via GraphQL Octadesk
Acesse: http://localhost:5050/painel_n2_cdm.html

Renova o token JWT automaticamente a cada ~35h usando suas credenciais.
"""

import json, os, threading, time, base64, sqlite3, hashlib, secrets
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

_BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
# RAILWAY_VOLUME_MOUNT_PATH é setado automaticamente quando um Volume é anexado
_DATA_DIR   = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', _BASE_DIR)
CONFIG_FILE = os.path.join(_BASE_DIR,  'cdm_config.json')
DB_FILE     = os.path.join(_DATA_DIR,  'cdm_edits.db')
PORT = int(os.environ.get('PORT', 5050))
# Em ambiente cloud, o config vive em memória (env vars) e não em arquivo
_MEM_CONFIG = {}
_DB_LOCK = threading.Lock()
# Salt para hash de senhas — pode customizar via env var
_SALT = os.environ.get('CDM_SALT', 'cdm_painel_n2_2024_secure')

GQL_URL  = 'https://southamerica-east1-001.prod.octadesk.services/tickets/api/graphql/query'
AUTH_URL = 'https://southamerica-east1-001.pantheon.octadesk.services/nucleus-auth/auth'

# tenantId fixo do Octadesk CDM Contabilidade
CDM_TENANT_ID = '259538b2-895f-43fd-98f7-8f6bc3bab95e'
CDM_SUBDOMAIN = 'o216962-660'

GQL_QUERY = """
query ($externalQueries: [QueryFilterInputType]!, $propertySort: String!,
       $sortDirection: String!, $take: Int!, $queryType: TicketListSearchType!,
       $skip: Int!, $executeTotalItems: Boolean!) {
  ticketList(externalQueries: $externalQueries, propertySort: $propertySort,
             sortDirection: $sortDirection, take: $take, queryType: $queryType,
             skip: $skip, executeTotalItems: $executeTotalItems) {
    tickets {
      id
      number
      summary
      currentStatusName
      stateProgressName
      assignedName
      requesterName
      groupAssignedName
      organizationName
      openDate
      dueDate
      lastDateUpdate
      priorityName
      reportedAsSpam
      sla { dueDate __typename }
      __typename
    }
    __typename
  }
}
"""

# ── DATABASE (edits + usuários + sessões) ────────────────────────────────────
def init_db():
    with _DB_LOCK:
        con = sqlite3.connect(DB_FILE)
        # Tabela de edits de tickets
        con.execute('''CREATE TABLE IF NOT EXISTS edits (
            numero       TEXT PRIMARY KEY,
            criticidade  TEXT DEFAULT '',
            prazo        TEXT DEFAULT '',
            motivo       TEXT DEFAULT '',
            status       TEXT DEFAULT 'Em Aberto',
            updated_at   REAL
        )''')
        # Tabela de usuários do painel
        con.execute('''CREATE TABLE IF NOT EXISTS users (
            email        TEXT PRIMARY KEY,
            name         TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            created_at   REAL
        )''')
        # Tabela de sessões ativas
        con.execute('''CREATE TABLE IF NOT EXISTS sessions (
            token        TEXT PRIMARY KEY,
            email        TEXT NOT NULL,
            expires_at   REAL NOT NULL,
            created_at   REAL
        )''')
        con.commit()
        # Cria usuário admin a partir das variáveis de ambiente
        admin_email = os.environ.get('CDM_ADMIN_EMAIL', '').strip().lower()
        admin_pw    = os.environ.get('CDM_ADMIN_PASSWORD', '').strip()
        admin_name  = os.environ.get('CDM_ADMIN_NAME', 'Administrador').strip()
        if admin_email and admin_pw:
            exists = con.execute('SELECT 1 FROM users WHERE email=?', (admin_email,)).fetchone()
            if not exists:
                con.execute('INSERT INTO users (email, name, password_hash, created_at) VALUES (?,?,?,?)',
                            (admin_email, admin_name, _hash_pw(admin_pw), time.time()))
                con.commit()
                print(f'[AUTH] Admin criado: {admin_email}')
            else:
                # Atualiza a senha do admin se a env var mudar
                con.execute('UPDATE users SET password_hash=?, name=? WHERE email=?',
                            (_hash_pw(admin_pw), admin_name, admin_email))
                con.commit()
        else:
            print('[AUTH] ⚠️  Defina CDM_ADMIN_EMAIL e CDM_ADMIN_PASSWORD nas variáveis de ambiente!')
        con.close()
    print(f'[DB] Banco pronto: {DB_FILE}')

# ── AUTH ──────────────────────────────────────────────────────────────────────
def _hash_pw(password):
    return hashlib.sha256((_SALT + password).encode('utf-8')).hexdigest()

def db_validate_login(email, password):
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            row = con.execute('SELECT name, password_hash FROM users WHERE email=?',
                              (email.lower().strip(),)).fetchone()
            con.close()
            if not row:
                return None, 'E-mail não encontrado'
            if row[1] != _hash_pw(password):
                return None, 'Senha incorreta'
            return {'email': email.lower().strip(), 'name': row[0]}, None
        except Exception as e:
            return None, str(e)

def db_create_session(email, hours=24):
    token = secrets.token_urlsafe(40)
    expires = time.time() + hours * 3600
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            # Remove sessões antigas do mesmo usuário (mantém máx 5)
            old = con.execute('SELECT token FROM sessions WHERE email=? ORDER BY created_at DESC LIMIT -1 OFFSET 4',
                              (email,)).fetchall()
            for (t,) in old:
                con.execute('DELETE FROM sessions WHERE token=?', (t,))
            con.execute('INSERT INTO sessions (token, email, expires_at, created_at) VALUES (?,?,?,?)',
                        (token, email, expires, time.time()))
            con.commit()
            con.close()
            return token
        except Exception as e:
            print(f'[AUTH] Erro ao criar sessão: {e}')
            return None

def db_validate_session(token):
    if not token:
        return None
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            row = con.execute('SELECT email, expires_at FROM sessions WHERE token=?', (token,)).fetchone()
            con.close()
            if not row:
                return None
            if row[1] < time.time():
                return None  # expirada
            return row[0]
        except:
            return None

def db_delete_session(token):
    if not token:
        return
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            con.execute('DELETE FROM sessions WHERE token=?', (token,))
            con.commit()
            con.close()
        except:
            pass

def db_list_users():
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            rows = con.execute('SELECT email, name, created_at FROM users ORDER BY created_at').fetchall()
            con.close()
            return [{'email': r[0], 'name': r[1], 'created_at': r[2]} for r in rows]
        except:
            return []

def db_add_user(email, password, name=''):
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            exists = con.execute('SELECT 1 FROM users WHERE email=?', (email,)).fetchone()
            if exists:
                con.execute('UPDATE users SET password_hash=?, name=? WHERE email=?',
                            (_hash_pw(password), name, email))
            else:
                con.execute('INSERT INTO users (email, name, password_hash, created_at) VALUES (?,?,?,?)',
                            (email, name, _hash_pw(password), time.time()))
            con.commit()
            con.close()
            return True, None
        except Exception as e:
            return False, str(e)

def db_delete_user(email):
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            con.execute('DELETE FROM users WHERE email=?', (email,))
            con.execute('DELETE FROM sessions WHERE email=?', (email,))
            con.commit()
            con.close()
            return True
        except:
            return False

def db_get_all():
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            con.row_factory = sqlite3.Row
            rows = con.execute('SELECT * FROM edits').fetchall()
            con.close()
            return {r['numero']: {
                'criticidade': r['criticidade'] or '',
                'prazo':       r['prazo']       or '',
                'motivo':      r['motivo']      or '',
                'status':      r['status']      or 'Em Aberto',
            } for r in rows}
        except Exception as e:
            print(f'[DB] Erro ao ler edits: {e}')
            return {}

def db_save_edit(numero, data):
    with _DB_LOCK:
        try:
            con = sqlite3.connect(DB_FILE)
            con.execute('''INSERT INTO edits (numero, criticidade, prazo, motivo, status, updated_at)
                           VALUES (?,?,?,?,?,?)
                           ON CONFLICT(numero) DO UPDATE SET
                             criticidade=excluded.criticidade,
                             prazo=excluded.prazo,
                             motivo=excluded.motivo,
                             status=excluded.status,
                             updated_at=excluded.updated_at''',
                        (numero,
                         data.get('criticidade',''),
                         data.get('prazo',''),
                         data.get('motivo',''),
                         data.get('status','Em Aberto'),
                         time.time()))
            con.commit()
            con.close()
            return True
        except Exception as e:
            print(f'[DB] Erro ao salvar edit: {e}')
            return False

# ── CONFIG ────────────────────────────────────────────────────────────────────
def load_config():
    cfg = {}
    # 1. Tenta arquivo local (desenvolvimento)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
        except Exception:
            pass
    # 2. Sobrepõe com in-memory (JWT renovado em runtime)
    cfg.update(_MEM_CONFIG)
    # 3. Variáveis de ambiente têm prioridade máxima (Railway/cloud)
    for env_key, cfg_key in [
        ('CDM_EMAIL',     'email'),
        ('CDM_PASSWORD',  'password'),
        ('CDM_TENANT_ID', 'tenantId'),
        ('CDM_SUBDOMAIN', 'subdomain'),
    ]:
        v = os.environ.get(env_key)
        if v:
            cfg[cfg_key] = v
    cfg.setdefault('tenantId', CDM_TENANT_ID)
    cfg.setdefault('subdomain', CDM_SUBDOMAIN)
    return cfg

def save_config(data):
    global _MEM_CONFIG
    _MEM_CONFIG.update(data)          # sempre salva em memória
    try:                              # tenta arquivo (local); silencia erros em cloud
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# ── JWT UTILS ─────────────────────────────────────────────────────────────────
def get_jwt_expiry(token):
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return None
        payload = parts[1]
        payload += '=' * (-len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode()))
        return decoded.get('exp')
    except Exception:
        return None

def jwt_hours_left(token):
    exp = get_jwt_expiry(token)
    if not exp:
        return None
    return max(0, round((exp - time.time()) / 3600, 1))

# ── LOGIN / REFRESH ───────────────────────────────────────────────────────────
def do_login(cfg):
    email     = cfg.get('email', '').strip()
    password  = cfg.get('password', '').strip()
    tenant_id = cfg.get('tenantId', CDM_TENANT_ID).strip()
    subdomain = cfg.get('subdomain', CDM_SUBDOMAIN).strip()

    if not email or not password:
        return None, 'E-mail e senha não configurados'

    body = json.dumps({
        'userName': email,
        'password': password,
        'tenantId': tenant_id,
    }).encode('utf-8')

    headers = {
        'Content-Type':  'application/json;charset=UTF-8',
        'Accept':        'application/json, text/plain, */*',
        'Origin':        'https://app.octadesk.com',
        'Referer':       'https://app.octadesk.com/login',
        'appsubdomain':  subdomain,
    }

    try:
        req = Request(AUTH_URL, data=body, headers=headers, method='POST')
        with urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        # jwtoken é o token correto para a API GraphQL do Octadesk
        token = (result.get('jwtoken') or result.get('token') or
                 result.get('accessToken') or result.get('jwt') or
                 result.get('bearerToken'))

        if not token:
            inner = result.get('data') or {}
            token = inner.get('jwtoken') or inner.get('token') or inner.get('accessToken')

        if token:
            print(f'[JWT] Login OK — token válido por {jwt_hours_left(token)}h')
            return token, None

        print(f'[JWT] Resposta do login: {list(result.keys())}')
        return None, f'Token não encontrado. Campos: {list(result.keys())}'

    except HTTPError as e:
        raw = e.read().decode('utf-8', errors='replace')[:300]
        return None, f'HTTP {e.code}: {raw}'
    except Exception as e:
        return None, str(e)

def maybe_refresh(force=False):
    cfg = load_config()
    has_creds = bool(cfg.get('email') and cfg.get('password'))
    if not has_creds:
        return False, 'Sem credenciais'

    token = cfg.get('jwtToken', '')
    needs = force or not token

    if not needs and token:
        hl = jwt_hours_left(token)
        if hl is not None:
            needs = hl < 6
            if not needs:
                return False, f'Token OK ({hl}h restantes)'
        else:
            last = cfg.get('lastTokenRefresh', 0)
            needs = (time.time() - last) > 35 * 3600

    if not needs:
        return False, 'Token ainda válido'

    new_token, err = do_login(cfg)
    if err:
        print(f'[JWT] Erro ao renovar: {err}')
        return False, err

    cfg['jwtToken']         = new_token
    cfg['lastTokenRefresh'] = time.time()
    save_config(cfg)
    return True, 'Token renovado'

def auto_refresh_loop():
    print('[JWT] Auto-refresh ativo — verifica a cada 30 min')
    while True:
        time.sleep(1800)
        try:
            maybe_refresh()
        except Exception as e:
            print(f'[JWT] Erro no loop: {e}')

# ── GRAPHQL ───────────────────────────────────────────────────────────────────
def gql_headers(cfg):
    return {
        'Authorization': f'Bearer {cfg.get("jwtToken", "")}',
        'appsubdomain':  cfg.get('subdomain', CDM_SUBDOMAIN),
        'content-type':  'application/json',
        'accept':        '*/*',
        'origin':        'https://app.octadesk.com',
        'referer':       'https://app.octadesk.com/',
    }

def fetch_tickets_graphql(cfg):
    subdomain = cfg.get('subdomain', '').strip()
    jwt       = cfg.get('jwtToken', '').strip()

    if not subdomain or not jwt:
        return None, 'Configure as credenciais e clique em Conectar'

    hdrs        = gql_headers(cfg)
    all_tickets = []
    take        = 200
    seen_ids    = set()

    for qtype in ['UnresolvedTickets', 'NewTickets', 'WaitingTickets']:
        skip = 0
        while True:
            payload = {
                'operationName': None,
                'query': GQL_QUERY,
                'variables': {
                    'externalQueries':  [],
                    'propertySort':     'OpenDate',
                    'sortDirection':    'desc',
                    'take':             take,
                    'queryType':        qtype,
                    'skip':             skip,
                    'executeTotalItems': skip == 0,
                    'includeArchiveds': False,
                    'idCustomList':     '',
                    'area':             '',
                }
            }
            data = json.dumps(payload).encode()
            try:
                req = Request(GQL_URL, data=data, headers=hdrs, method='POST')
                with urlopen(req, timeout=25) as resp:
                    body = json.loads(resp.read().decode('utf-8'))
            except HTTPError as e:
                raw = e.read().decode('utf-8', errors='replace')[:200]
                return None, f'HTTP {e.code}: {raw}'
            except URLError as e:
                return None, f'Conexão falhou: {e.reason}'
            except Exception as e:
                return None, str(e)

            if body.get('errors'):
                errs = '; '.join(e.get('message', '?') for e in body['errors'])
                if 'unauthorized' in errs.lower() or 'authentication' in errs.lower():
                    print('[JWT] Token inválido — tentando renovar...')
                    maybe_refresh(force=True)
                return None, f'GraphQL erro: {errs}'

            batch = (body.get('data') or {}).get('ticketList', {}).get('tickets', [])
            if not batch:
                break

            for t in batch:
                tid = t.get('id')
                if tid and tid not in seen_ids:
                    seen_ids.add(tid)
                    all_tickets.append(t)

            if len(batch) < take:
                break
            skip += take

    print(f'[OK] {len(all_tickets)} tickets carregados')
    return all_tickets, None

# ── HANDLER ───────────────────────────────────────────────────────────────────
class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.dirname(os.path.abspath(__file__)), **kwargs)

    def log_message(self, fmt, *args):
        try:
            if args and isinstance(args[0], str) and '/tickets' in args[0]:
                return
        except Exception:
            pass
        super().log_message(fmt, *args)

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type',   'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def get_token(self):
        return self.headers.get('X-CDM-Token', '')

    def check_auth(self):
        """Valida sessão. Retorna email do usuário ou None (já envia 401)."""
        email = db_validate_session(self.get_token())
        if not email:
            self.send_json({'error': 'Sessão inválida. Faça login novamente.', 'code': 401}, 401)
        return email

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin',  '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-CDM-Token')
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?')[0]

        # ── Rotas públicas (sem autenticação) ──────────────────────────────
        if path == '/ping':
            self.send_json({'ok': True})
            return

        if path == '/session':
            email = db_validate_session(self.get_token())
            self.send_json({'ok': bool(email), 'email': email or ''})
            return

        if path == '/users':
            if not self.check_auth():
                return
            self.send_json({'users': db_list_users()})
            return

        # ── Rotas protegidas ───────────────────────────────────────────────
        if path in ['/config', '/tickets', '/refresh', '/edits', '/sample']:
            if not self.check_auth():
                return

        if path == '/config':
            cfg   = load_config()
            token = cfg.get('jwtToken', '')
            hl    = jwt_hours_left(token) if token else None
            self.send_json({
                'subdomain':      cfg.get('subdomain', CDM_SUBDOMAIN),
                'email':          cfg.get('email', ''),
                'hasCredentials': bool(cfg.get('email') and cfg.get('password')),
                'hasJwt':         bool(token),
                'tokenHoursLeft': hl,
            })

        elif path == '/tickets':
            cfg = load_config()
            tickets, err = fetch_tickets_graphql(cfg)
            if err:
                self.send_json({'error': err})
            else:
                self.send_json({'tickets': tickets, 'total': len(tickets)})

        elif path == '/refresh':
            ok, msg = maybe_refresh(force=True)
            cfg = load_config()
            self.send_json({'ok': ok, 'msg': msg, 'hasJwt': bool(cfg.get('jwtToken'))})

        elif path == '/edits':
            self.send_json(db_get_all())

        elif path == '/sample':
            cfg = load_config()
            tickets, err = fetch_tickets_graphql(cfg)
            if err:
                self.send_json({'error': err})
            else:
                sample = tickets[:3] if tickets else []
                self.send_json({'sample': sample, 'total': len(tickets)})

        else:
            super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        try:
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            body = {}

        # ── Rota pública: login ────────────────────────────────────────────
        if self.path == '/login':
            email    = str(body.get('email', '')).strip().lower()
            password = str(body.get('password', '')).strip()
            if not email or not password:
                self.send_json({'ok': False, 'error': 'Preencha e-mail e senha'}, 400)
                return
            user, err = db_validate_login(email, password)
            if err:
                print(f'[AUTH] Falha de login para {email}: {err}')
                self.send_json({'ok': False, 'error': err}, 401)
                return
            token = db_create_session(email)
            print(f'[AUTH] Login: {email}')
            self.send_json({'ok': True, 'token': token, 'name': user['name'], 'email': email})
            return

        # ── Rota pública: logout ───────────────────────────────────────────
        if self.path == '/logout':
            db_delete_session(self.get_token())
            self.send_json({'ok': True})
            return

        # ── Rotas protegidas ───────────────────────────────────────────────
        if not self.check_auth():
            return

        if self.path == '/config':
            existing = load_config()
            if body.get('password', '').startswith('•'):
                body['password'] = existing.get('password', '')
            body.setdefault('tenantId', CDM_TENANT_ID)
            body.setdefault('subdomain', CDM_SUBDOMAIN)
            existing.update(body)
            save_config(existing)
            self.send_json({'ok': True})

        elif self.path == '/edits':
            numero = str(body.get('numero', '')).strip()
            if not numero:
                self.send_json({'ok': False, 'error': 'numero obrigatório'}, 400)
                return
            ok = db_save_edit(numero, body)
            self.send_json({'ok': ok})

        elif self.path == '/users':
            action = body.get('action', '')
            if action == 'add':
                email  = str(body.get('email', '')).strip().lower()
                pw     = str(body.get('password', '')).strip()
                name   = str(body.get('name', '')).strip()
                if not email or not pw:
                    self.send_json({'ok': False, 'error': 'E-mail e senha obrigatórios'}, 400)
                    return
                ok, err = db_add_user(email, pw, name)
                self.send_json({'ok': ok, 'error': err})
            elif action == 'delete':
                email = str(body.get('email', '')).strip().lower()
                ok = db_delete_user(email)
                self.send_json({'ok': ok})
            else:
                self.send_json({'ok': False, 'error': 'Ação inválida'}, 400)

        else:
            self.send_response(404)
            self.end_headers()

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Inicia banco de dados de edits
    init_db()

    # Garante config base
    cfg = load_config()
    changed = False
    if not cfg.get('tenantId'):
        cfg['tenantId'] = CDM_TENANT_ID
        changed = True
    if not cfg.get('subdomain'):
        cfg['subdomain'] = CDM_SUBDOMAIN
        changed = True
    if changed:
        save_config(cfg)

    # Tenta renovar token na inicialização (após 3s, em background)
    threading.Thread(target=lambda: (time.sleep(3), maybe_refresh()), daemon=True).start()

    # Loop de auto-refresh em background
    threading.Thread(target=auto_refresh_loop, daemon=True).start()

    host = '0.0.0.0'  # necessário para cloud (Railway, Render, etc.)
    server = HTTPServer((host, PORT), Handler)
    print(f'\n✅  Servidor CDM N2 rodando em http://{host}:{PORT}')
    print(f'   → Painel: http://localhost:{PORT}/painel_n2_cdm.html')
    print(f'   → Ngrok:  https://vagabond-ellipse-frigidity.ngrok-free.dev/painel_n2_cdm.html')
    print(f'   🔄 Token JWT renovado automaticamente — sem intervenção manual')
    print(f'   → Ctrl+C para encerrar\n')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nServidor encerrado.')
