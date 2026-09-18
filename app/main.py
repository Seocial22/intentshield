import base64, hashlib, json, os, secrets, sqlite3, uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

APP_DIR=os.path.dirname(os.path.abspath(__file__))
BASE=os.path.dirname(APP_DIR)
STORAGE_DIR="/tmp" if os.environ.get("VERCEL") else BASE
DB=os.path.join(STORAGE_DIR,"intentshield.db")
KEYFILE=os.path.join(STORAGE_DIR,"signing_key.bin")

def now(): return datetime.now(timezone.utc)
def iso(x): return x.isoformat().replace("+00:00","Z")
def b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64d(s): return base64.urlsafe_b64decode(s+"="*((4-len(s)%4)%4))
def canonical(x): return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def get_private():
    if os.path.exists(KEYFILE):
        return Ed25519PrivateKey.from_private_bytes(open(KEYFILE,"rb").read())
    k=Ed25519PrivateKey.generate()
    with open(KEYFILE,"wb") as f: f.write(k.private_bytes_raw())
    return k

PRIVATE=get_private()
PUBLIC=PRIVATE.public_key()
KEY_ID=hashlib.sha256(PUBLIC.public_bytes(Encoding.Raw,PublicFormat.Raw)).hexdigest()[:16]

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS intents(id TEXT PRIMARY KEY,customer_id TEXT,payload TEXT,token TEXT,created_at TEXT,expires_at TEXT,status TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY,owner TEXT,name TEXT,scopes TEXT,created_at TEXT,revoked INTEGER DEFAULT 0)")
    c.execute("CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,journey_id TEXT,event_type TEXT,actor TEXT,data TEXT,ts TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS edges(id TEXT PRIMARY KEY,journey_id TEXT,source TEXT,target TEXT,relation TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS credentials(user_id TEXT PRIMARY KEY,challenge TEXT,credential_id TEXT,public_key TEXT)")
    c.commit(); return c

def add_event(c,j,t,a,data):
    eid="evt_"+uuid.uuid4().hex[:10]
    c.execute("INSERT INTO events VALUES(?,?,?,?,?,?)",(eid,j,t,a,json.dumps(data),iso(now())))
    return eid
def add_edge(c,j,s,t,r):
    c.execute("INSERT INTO edges VALUES(?,?,?,?,?)",("ed_"+uuid.uuid4().hex[:10],j,s,t,r))

def sign_intent(iid,payload,exp):
    ph=hashlib.sha256(canonical(payload)).hexdigest()
    body={"v":1,"alg":"Ed25519","kid":KEY_ID,"intent_id":iid,"iat":iso(now()),"exp":iso(exp),"payload_hash":ph}
    return b64e(canonical(body))+"."+b64e(PRIVATE.sign(canonical(body)))

def verify_signature(token):
    try:
        b,s=token.split(".")
        body=json.loads(b64d(b))
        PUBLIC.verify(b64d(s),canonical(body))
        return body
    except Exception as e: raise HTTPException(400,"Invalid signature")

app=FastAPI(title="IntentShield API",version="0.2.0")

@app.middleware("http")
async def fix_path_middleware(request: Request, call_next):
    forwarded = request.headers.get("x-matched-path") or request.headers.get("x-forwarded-uri")
    if forwarded and not forwarded.startswith("/api/index.py"):
        request.scope["path"] = forwarded.split("?")[0]
    else:
        path = request.scope.get("path", "")
        for prefix in ("/api/index.py", "/api/index", "/api"):
            if path == prefix:
                request.scope["path"] = "/"
                break
            elif path.startswith(prefix + "/"):
                request.scope["path"] = path[len(prefix):]
                break
    return await call_next(request)

app.mount("/static",StaticFiles(directory=os.path.join(APP_DIR,"static")),name="static")
templates=Jinja2Templates(directory=os.path.join(APP_DIR,"templates"))

class AgentIn(BaseModel):
    owner:str; name:str; max_amount:float=Field(gt=0); currency:str="EUR"
    allowed_recipients:list[str]=[]; max_transactions:int=1; expires_hours:int=24
class IntentIn(BaseModel):
    customer_id:str; amount:float=Field(gt=0); currency:str="EUR"; recipient:str
    purpose:Optional[str]=None; max_amount:Optional[float]=None; agent_id:Optional[str]=None; expires_minutes:int=15
class TxIn(BaseModel):
    intent_id:str; amount:float=Field(gt=0); currency:str="EUR"; recipient:str
    initiator_type:str="HUMAN"; agent_id:Optional[str]=None; remote_access:bool=False
    new_beneficiary:bool=False; external_scam_signal:bool=False

@app.get("/api/index.py", response_class=HTMLResponse)
@app.get("/api/index", response_class=HTMLResponse)
@app.get("/api", response_class=HTMLResponse)
@app.get("/",response_class=HTMLResponse)
def home(request:Request):
    return templates.TemplateResponse("index.html",{"request":request})

@app.get("/health")
def health(): return {"status":"ok","key_id":KEY_ID}

@app.get("/v1/public-key")
def public_key():
    return {"kid":KEY_ID,"alg":"Ed25519","public_key":b64e(PUBLIC.public_bytes(Encoding.Raw,PublicFormat.Raw))}

@app.post("/v1/agents")
def create_agent(x:AgentIn):
    c=db(); aid="agent_"+uuid.uuid4().hex[:10]; exp=now()+timedelta(hours=x.expires_hours)
    scope={"max_amount":x.max_amount,"currency":x.currency,"allowed_recipients":x.allowed_recipients,
           "max_transactions":x.max_transactions,"expires_at":iso(exp)}
    c.execute("INSERT INTO agents VALUES(?,?,?,?,?,0)",(aid,x.owner,x.name,json.dumps(scope),iso(now())))
    c.commit(); c.close()
    return {"agent_id":aid,"name":x.name,"owner":x.owner,"delegation":scope}

@app.post("/v1/agents/{agent_id}/revoke")
def revoke(agent_id:str):
    c=db()
    if not c.execute("SELECT id FROM agents WHERE id=?",(agent_id,)).fetchone(): raise HTTPException(404,"Agent not found")
    c.execute("UPDATE agents SET revoked=1 WHERE id=?",(agent_id,)); c.commit(); c.close()
    return {"agent_id":agent_id,"status":"REVOKED"}

@app.post("/v1/intents")
def create_intent(x:IntentIn):
    c=db(); iid="int_"+uuid.uuid4().hex[:10]; exp=now()+timedelta(minutes=x.expires_minutes)
    maximum=x.max_amount if x.max_amount is not None else x.amount
    if x.agent_id:
        a=c.execute("SELECT * FROM agents WHERE id=?",(x.agent_id,)).fetchone()
        if not a or a["revoked"]: raise HTTPException(400,"Agent unavailable")
        scope=json.loads(a["scopes"])
        if maximum>scope["max_amount"]: raise HTTPException(400,"Intent exceeds agent ceiling")
    payload={"customer_id":x.customer_id,"action":"payment","amount":x.amount,"currency":x.currency,
             "recipient":x.recipient,"purpose":x.purpose,"max_amount":maximum,"agent_id":x.agent_id}
    token=sign_intent(iid,payload,exp)
    c.execute("INSERT INTO intents VALUES(?,?,?,?,?,?,?)",(iid,x.customer_id,json.dumps(payload),token,iso(now()),iso(exp),"ACTIVE"))
    journey="journey_"+uuid.uuid4().hex[:10]
    e1=add_event(c,journey,"INTENT_CREATED","HUMAN",payload)
    e2=add_event(c,journey,"AUTHORIZATION_ISSUED","INTENTSHIELD",{"intent_id":iid,"key_id":KEY_ID})
    add_edge(c,journey,e1,e2,"created")
    c.commit(); c.close()
    return {"intent_id":iid,"token":token,"payload":payload,"expires_at":iso(exp),"journey_id":journey}

@app.post("/v1/intents/{intent_id}/verify")
def verify_intent(intent_id:str):
    c=db(); r=c.execute("SELECT * FROM intents WHERE id=?",(intent_id,)).fetchone(); c.close()
    if not r: raise HTTPException(404,"Intent not found")
    body=verify_signature(r["token"]); payload=json.loads(r["payload"])
    good=body["payload_hash"]==hashlib.sha256(canonical(payload)).hexdigest()
    expired=datetime.fromisoformat(body["exp"].replace("Z","+00:00"))<now()
    return {"valid":good and not expired,"signature_valid":True,"payload_hash_valid":good,"expired":expired,"key_id":body["kid"]}

@app.post("/v1/transactions/evaluate")
def evaluate(x:TxIn):
    c=db(); r=c.execute("SELECT * FROM intents WHERE id=?",(x.intent_id,)).fetchone()
    if not r: raise HTTPException(404,"Intent not found")
    intent=json.loads(r["payload"]); score=0; violations=[]
    if x.currency!=intent["currency"]: score+=35; violations.append("CURRENCY_MISMATCH")
    if abs(x.amount-intent["amount"])>0.0001: score+=35; violations.append("AMOUNT_MISMATCH")
    if x.amount>intent["max_amount"]+0.0001: score+=20; violations.append("MAX_AMOUNT_EXCEEDED")
    if x.recipient.lower()!=intent["recipient"].lower(): score+=35; violations.append("RECIPIENT_MISMATCH")
    if x.initiator_type=="AI_AGENT":
        a=c.execute("SELECT * FROM agents WHERE id=?",(x.agent_id,)).fetchone()
        if not a or a["revoked"]: score+=40; violations.append("AGENT_NOT_AUTHORIZED")
        else:
            s=json.loads(a["scopes"])
            if x.amount>s["max_amount"]: score+=30; violations.append("AGENT_SCOPE_VIOLATION")
            if s["allowed_recipients"] and x.recipient not in s["allowed_recipients"]:
                score+=30; violations.append("AGENT_RECIPIENT_SCOPE_VIOLATION")
    if x.remote_access: score+=15; violations.append("REMOTE_ACCESS_SIGNAL")
    if x.new_beneficiary: score+=8; violations.append("NEW_BENEFICIARY")
    if x.external_scam_signal: score+=20; violations.append("EXTERNAL_SCAM_SIGNAL")
    score=min(100,score); decision="BLOCK" if score>=70 else ("STEP_UP" if score>=35 else "ALLOW")
    journey="journey_"+uuid.uuid4().hex[:10]
    e1=add_event(c,journey,"TRANSACTION_ATTEMPT",x.initiator_type,x.model_dump())
    e2=add_event(c,journey,"INTENT_CHECK","INTENTSHIELD",{"intent_id":x.intent_id,"risk_score":score,"violations":violations})
    e3=add_event(c,journey,"DECISION","INTENTSHIELD",{"decision":decision})
    add_edge(c,journey,e1,e2,"evaluated_against"); add_edge(c,journey,e2,e3,"decision")
    c.commit(); c.close()
    return {"transaction_id":"txn_"+uuid.uuid4().hex[:10],"journey_id":journey,"risk_score":score,"decision":decision,
            "intent_match":not any("MISMATCH" in v for v in violations),"violations":violations}

@app.get("/v1/journeys/{journey_id}")
def get_journey(journey_id:str):
    c=db()
    nodes=[dict(r,data=json.loads(r["data"])) for r in c.execute("SELECT * FROM events WHERE journey_id=? ORDER BY ts",(journey_id,)).fetchall()]
    edges=[dict(r) for r in c.execute("SELECT * FROM edges WHERE journey_id=?",(journey_id,)).fetchall()]
    c.close(); return {"journey_id":journey_id,"nodes":nodes,"edges":edges}

@app.post("/v1/webauthn/register/options")
def webauthn_options(request:Request, user_id:str="demo-user"):
    challenge=b64e(secrets.token_bytes(32)); c=db()
    c.execute("INSERT OR REPLACE INTO credentials(user_id,challenge,credential_id,public_key) VALUES(?,?,?,?)",(user_id,challenge,"",""))
    c.commit(); c.close()
    rp_id = request.url.hostname or "localhost"
    if rp_id in ("127.0.0.1", "0.0.0.0"):
        rp_id = "localhost"
    return {"challenge":challenge,"rp":{"name":"IntentShield","id":rp_id},
            "user":{"id":b64e(user_id.encode()),"name":user_id,"displayName":"IntentShield Demo"},
            "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"timeout":60000,"attestation":"none"}
