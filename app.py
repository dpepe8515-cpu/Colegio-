import os,sqlite3,secrets,hashlib,time,smtplib,re,base64
from datetime import datetime,timedelta
from email.message import EmailMessage
from functools import wraps
from flask import Flask,g,request,session,redirect,render_template,abort,flash,Response
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash,check_password_hash
from templates import T
from assets_data import CSS,JS,LOGO
PG=os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL')
D=os.environ.get('DATA_DIR') or ('/tmp/colegio' if os.environ.get('VERCEL') else os.path.join(os.path.dirname(os.path.abspath(__file__)),'data'))
os.makedirs(D,exist_ok=True);DB=os.path.join(D,'app.db')
def secret():
    if os.environ.get('SECRET_KEY'): return os.environ['SECRET_KEY']
    if PG: raise RuntimeError('Falta la variable SECRET_KEY')
    p=D+'/secret.key'
    if not os.path.exists(p): open(p,'w').write(secrets.token_hex(32))
    return open(p).read()
app=Flask(__name__,static_folder=None);app.secret_key=secret();app.jinja_loader=DictLoader(T)
app.config.update(MAX_CONTENT_LENGTH=4*1024*1024,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('PROD')=='1',PERMANENT_SESSION_LIFETIME=timedelta(hours=8))
SCHEMA='''
create table if not exists users(id integer primary key,email text unique not null,pw text not null,role text not null,active int default 1);
create table if not exists tokens(h text primary key,kind text,email text,role text,user_id int,exp real,used int default 0);
create table if not exists attempts(ip text,ts real);
create table if not exists settings(k text primary key,v text);
create table if not exists programs(id integer primary key,name text,level text,description text,subjects text);
create table if not exists news(id integer primary key,title text,body text,date text);
create table if not exists photos(id integer primary key,title text,description text,category text,file text,sort int default 0);
create table if not exists applications(id integer primary key,code text unique,created text,student text,birth text,level text,guardian text,email text,phone text,status text default 'Solicitud recibida',notes text default '');
create table if not exists prices(id integer primary key,concept text,period text,amount_cents int,due text,active int default 1);
create table if not exists price_history(id integer primary key,price_id int,old_cents int,new_cents int,by_user text,ts text);
create table if not exists obligations(id integer primary key,app_id int,concept text,period text,amount_cents int,currency text default 'USD',due text,status text default 'pendiente');
create table if not exists transfers(id integer primary key,obl_id int,reference text,file text,status text default 'pendiente',reason text,reviewer text,ts text,reviewed text);
create table if not exists payments(id integer primary key,obl_id int,method text,amount_cents int,currency text,reference text,status text,confirmed_by text,ts text);
create table if not exists audit(id integer primary key,who text,action text,ts text);
create table if not exists outbox(id integer primary key,to_addr text,subject text,body text,sent int default 0,tries int default 0,err text);
create table if not exists files(name text primary key,ctype text,data bytea);
'''
def now(): return datetime.now().isoformat(timespec='seconds')
class R(dict):
    def __getitem__(s,k): return list(s.values())[k] if isinstance(k,int) else dict.__getitem__(s,k)
def connect():
    if PG:
        import psycopg
        def rf(cur):
            n=[c.name for c in cur.description]
            return lambda v:R(zip(n,v))
        return psycopg.connect(PG,autocommit=True,row_factory=rf)
    c=sqlite3.connect(DB);c.row_factory=lambda cur,row:R(zip([d[0] for d in cur.description],row));return c
def db():
    if 'db' not in g: g.db=connect()
    return g.db
def q(sql,a=(),one=False):
    c=db()
    if PG: sql=sql.replace('?','%s')
    cur=c.execute(sql,list(a))
    r=cur.fetchall() if cur.description else []
    if not PG: c.commit()
    return (r[0] if r else None) if one else r
def init():
    c=connect();sc=SCHEMA
    if PG: sc=sc.replace('integer primary key','serial primary key').replace(' real',' double precision')
    for st in sc.split(';'):
        if st.strip(): c.execute(st)
    e,p=os.environ.get('ADMIN_EMAIL'),os.environ.get('ADMIN_PASSWORD')
    if e and p and len(p)>=10 and not c.execute('select 1 from users limit 1').fetchall():
        c.execute('insert into users(email,pw,role) values(%s,%s,%s)' if PG else 'insert into users(email,pw,role) values(?,?,?)',(e.strip().lower(),generate_password_hash(p),'owner'))
    if not PG: c.commit()
    c.close()
@app.teardown_appcontext
def close(e=None):
    d=g.pop('db',None)
    if d: d.close()
def audit(a): q('insert into audit(who,action,ts) values(?,?,?)',(session.get('email','publico'),a,now()))
def setting(k,d=''):
    r=q('select v from settings where k=?',(k,),True);return r['v'] if r else d
def hsh(t): return hashlib.sha256(t.encode()).hexdigest()
def enqueue(to,subj,body): q('insert into outbox(to_addr,subject,body) values(?,?,?)',(to,subj,body))
def notify(roles,subj,body):
    for u in q('select email from users where active=1 and role in (%s)'%','.join('?'*len(roles)),roles): enqueue(u['email'],subj,body)
def send_pending():
    h=os.environ.get('SMTP_HOST')
    if not h: return 0
    n=0
    for m in q('select * from outbox where sent=0 and tries<5 order by id limit 10'):
        try:
            e=EmailMessage();e['From']=os.environ.get('SMTP_FROM',os.environ.get('SMTP_USER',''));e['To']=m['to_addr'];e['Subject']=m['subject'];e.set_content(m['body'])
            with smtplib.SMTP(h,int(os.environ.get('SMTP_PORT',587)),timeout=10) as sm:
                sm.starttls();sm.login(os.environ['SMTP_USER'],os.environ['SMTP_PASS']);sm.send_message(e)
            q('update outbox set sent=1 where id=?',(m['id'],));n+=1
        except Exception as ex: q('update outbox set tries=tries+1,err=? where id=?',(str(ex)[:200],m['id']))
    return n
def ip(): return (request.headers.get('x-forwarded-for','').split(',')[0].strip() or request.remote_addr or '')
def base_url(): return os.environ.get('BASE_URL',request.host_url.rstrip('/'))
PERMS={'owner':None,'secretaria':{'apps'},'finanzas':{'fin'}}
def need(p):
    def d(f):
        @wraps(f)
        def w(*a,**k):
            if 'uid' not in session: return redirect('/admin')
            u=q('select * from users where id=? and active=1',(session['uid'],),True)
            if not u: session.clear();return redirect('/admin')
            pr=PERMS.get(u['role'])
            if p and pr is not None and p not in pr: abort(403)
            g.user=u;return f(*a,**k)
        return w
    return d
@app.before_request
def csrf_check():
    if request.method=='POST':
        if not session.get('csrf') or not secrets.compare_digest(session['csrf'],request.form.get('csrf','')): abort(400)
@app.context_processor
def ctx():
    if 'csrf' not in session: session['csrf']=secrets.token_hex(16)
    from markupsafe import Markup
    return dict(csrf=lambda:Markup('<input type=hidden name=csrf value="%s">'%session['csrf']),S=setting,money=lambda c:'$%.2f'%(c/100))
@app.after_request
def hdr(r):
    r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';r.headers['Referrer-Policy']='same-origin'
    if request.method=='POST' and os.environ.get('SMTP_HOST'):
        try: send_pending()
        except Exception: pass
    r.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'"
    return r
def cents(s):
    from decimal import Decimal,InvalidOperation
    try: v=Decimal(s.replace(',','.'));assert v>=0;return int((v*100).to_integral_value())
    except Exception: raise ValueError('Importe inválido')
def save_file(f,exts,folder):
    ext=(f.filename.rsplit('.',1)[-1] if '.' in f.filename else '').lower()
    if ext not in exts: raise ValueError('Formato no permitido')
    head=f.read(8);f.seek(0)
    ok=(ext in('jpg','jpeg') and head[:3]==b'\xff\xd8\xff') or (ext=='png' and head[:4]==b'\x89PNG') or (ext=='webp' and head[:4]==b'RIFF') or (ext=='pdf' and head[:4]==b'%PDF')
    if not ok: raise ValueError('El archivo no coincide con su formato')
    n=('r_' if folder=='receipts' else '')+secrets.token_hex(12)+'.'+ext;q('insert into files(name,ctype,data) values(?,?,?)',(n,ext,f.read()));return n
# ---------- público ----------
@app.route('/')
def index():
    return render_template('index.html',programs=q('select * from programs'),news=q('select * from news order by date desc limit 6'),photos=q("select * from photos where category!='Portada' order by sort,id"),hero=q("select * from photos where category='Portada' order by sort,id limit 1",one=True),prices=q('select * from prices where active=1 order by id'))
@app.route('/static-media/<f>')
def media(f):
    r=q('select * from files where name=?',(f,),True)
    if not r or f.startswith('r_'): abort(404)
    ct={'jpg':'image/jpeg','jpeg':'image/jpeg','png':'image/png','webp':'image/webp'}.get(r['ctype'],'application/octet-stream')
    return Response(bytes(r['data']),mimetype=ct,headers={'Cache-Control':'public,max-age=86400'})
@app.route('/static/style.css')
def css(): return Response(CSS,mimetype='text/css',headers={'Cache-Control':'public,max-age=600'})
@app.route('/static/app.js')
def js(): return Response(JS,mimetype='application/javascript',headers={'Cache-Control':'public,max-age=600'})
@app.route('/static/logo.jpg')
def logo(): return Response(base64.b64decode(LOGO),mimetype='image/jpeg',headers={'Cache-Control':'public,max-age=86400'})
@app.route('/preinscripcion',methods=['GET','POST'])
def pre():
    progs=q('select * from programs')
    if request.method=='POST':
        f=request.form;e=[]
        v={k:f.get(k,'').strip() for k in('student','birth','level','guardian','email','phone')}
        if len(v['student'])<3: e.append('Escriba el nombre completo del estudiante.')
        if not re.match(r'^\d{4}-\d{2}-\d{2}$',v['birth']): e.append('Indique la fecha de nacimiento.')
        if len(v['guardian'])<3: e.append('Escriba el nombre del representante.')
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$',v['email']): e.append('Correo electrónico no válido.')
        if len(re.sub(r'\D','',v['phone']))<7: e.append('Teléfono no válido.')
        if not v['level']: e.append('Seleccione el nivel.')
        if not f.get('consent'): e.append('Debe aceptar el tratamiento de datos.')
        if e: return render_template('pre.html',progs=progs,errors=e,v=v),400
        code=secrets.token_hex(4).upper()
        q('insert into applications(code,created,student,birth,level,guardian,email,phone) values(?,?,?,?,?,?,?,?)',(code,now(),v['student'],v['birth'],v['level'],v['guardian'],v['email'].lower(),v['phone']))
        notify(['owner','secretaria'],'Nueva solicitud de matrícula','Se registró una nueva solicitud de matrícula (%s). Ingrese al panel para revisarla: %s/admin'%(code,base_url()))
        enqueue(v['email'].lower(),'Recibimos su solicitud','Su solicitud de matrícula fue recibida. Código de seguimiento: %s. El colegio la revisará y le contactará.'%code)
        return redirect('/gracias/'+code)
    return render_template('pre.html',progs=progs,errors=[],v={})
@app.route('/gracias/<code>')
def gracias(code): return render_template('thanks.html',code=code)
@app.route('/transferencia',methods=['GET','POST'])
def transf():
    msg=err=None
    if request.method=='POST':
        f=request.form
        try:
            a=q('select * from applications where code=? and email=?',(f.get('code','').strip().upper(),f.get('email','').strip().lower()),True)
            if not a: raise ValueError('Código o correo incorrectos.')
            o=q("select * from obligations where id=? and app_id=? and status='pendiente'",(f.get('obl','0'),a['id']),True)
            if not o: raise ValueError('Esa obligación no existe o ya no está pendiente.')
            ref=f.get('reference','').strip()
            if len(ref)<3: raise ValueError('Ingrese la referencia de la transferencia.')
            if q("select 1 from transfers where obl_id=? and status='pendiente'",(o['id'],),True): raise ValueError('Ya hay un comprobante en revisión para esta obligación.')
            fn=save_file(request.files['file'],{'jpg','jpeg','png','pdf'},'receipts') if request.files.get('file') and request.files['file'].filename else None
            q('insert into transfers(obl_id,reference,file,ts) values(?,?,?,?)',(o['id'],ref,fn,now()))
            notify(['owner','finanzas'],'Nueva transferencia por revisar','Se registró una transferencia pendiente de revisión. Ingrese al panel: %s/admin/transferencias'%base_url())
            msg='Recibimos su transferencia. Queda pendiente de revisión por el colegio.'
        except ValueError as x: err=str(x)
    return render_template('transf.html',msg=msg,err=err)
# ---------- auth ----------
def throttled(): 
    return q('select count(*) c from attempts where ip=? and ts>?',(ip(),time.time()-900),True)['c']>=5
@app.route('/admin',methods=['GET','POST'])
def login():
    if 'uid' in session and request.method=='GET': return redirect('/admin/panel')
    err=None
    if request.method=='POST':
        if throttled(): return render_template('login.html',err='Demasiados intentos. Espere 15 minutos.'),429
        u=q('select * from users where email=? and active=1',(request.form.get('email','').strip().lower(),),True)
        if u and check_password_hash(u['pw'],request.form.get('password','')):
            session.clear();session.permanent=True;session['uid']=u['id'];session['email']=u['email'];audit('inicio de sesión');return redirect('/admin/panel')
        q('insert into attempts values(?,?)',(ip(),time.time()));err='Correo o contraseña incorrectos.'
    return render_template('login.html',err=err)
@app.route('/admin/salir',methods=['POST'])
def logout(): session.clear();return redirect('/admin')
def mk_token(kind,email,role=None,uid=None,hours=2):
    t=secrets.token_urlsafe(32);q('insert into tokens values(?,?,?,?,?,?,0)',(hsh(t),kind,email,role,uid,time.time()+hours*3600));return t
@app.route('/admin/olvide',methods=['GET','POST'])
def forgot():
    sent=False
    if request.method=='POST':
        e=request.form.get('email','').strip().lower();u=q('select * from users where email=? and active=1',(e,),True)
        if u: enqueue(e,'Restablecer contraseña','Use este enlace (válido 2 horas): %s/admin/token/%s'%(base_url(),mk_token('reset',e,uid=u['id'])))
        sent=True
    return render_template('forgot.html',sent=sent)
@app.route('/admin/token/<t>',methods=['GET','POST'])
def use_token(t):
    r=q('select * from tokens where h=? and used=0 and exp>?',(hsh(t),time.time()),True)
    if not r: return render_template('forgot.html',sent=False,bad=True),404
    err=None
    if request.method=='POST':
        p=request.form.get('password','')
        if len(p)<10 or p!=request.form.get('password2'): err='La contraseña debe tener 10+ caracteres y coincidir.'
        else:
            if r['kind']=='invite':
                if q('select 1 from users where email=?',(r['email'],),True): abort(400)
                q('insert into users(email,pw,role) values(?,?,?)',(r['email'],generate_password_hash(p),r['role']))
            else: q('update users set pw=? where id=?',(generate_password_hash(p),r['user_id']))
            q('update tokens set used=1 where h=?',(r['h'],));return redirect('/admin')
    return render_template('setpw.html',err=err,kind=r['kind'])
# ---------- panel ----------
def nav(): return render_template('adm.html',page='x')
@app.route('/admin/panel')
@need(None)
def panel():
    c=lambda s,a=():q(s,a,True)[0]
    st=dict(nuevas=c("select count(*) from applications where status='Solicitud recibida'"),revision=c("select count(*) from applications where status='En revisión'"),pend=c("select count(*) from transfers where status='pendiente'"),venc=c("select count(*) from obligations where status='pendiente' and due!='' and due<?",(now()[:10],)),ing=c("select coalesce(sum(amount_cents),0) from payments where status='aprobado'"),act=q('select * from audit order by id desc limit 8'))
    return render_template('adm.html',page='panel',st=st)
STAT=['Solicitud recibida','En revisión','Pendiente de documentación','Pendiente de pago','Aceptada','Rechazada','Matrícula completada']
@app.route('/admin/solicitudes')
@need('apps')
def apps():
    s=request.args.get('s','');t=request.args.get('t','').strip()
    sql='select * from applications where 1=1';ar=[]
    if s: sql+=' and status=?';ar.append(s)
    if t: sql+=' and (student like ? or code=?)';ar+=['%'+t+'%',t.upper()]
    rows=q(sql+' order by id desc',ar)
    return render_template('adm.html',page='apps',rows=rows,STAT=STAT,s=s,t=t,prices=q('select * from prices where active=1'),obls=q('select * from obligations'))
@app.route('/admin/solicitud/<int:i>',methods=['POST'])
@need('apps')
def app_upd(i):
    s=request.form.get('status')
    if s not in STAT: abort(400)
    q('update applications set status=?,notes=? where id=?',(s,request.form.get('notes','')[:1000],i));audit('solicitud %s → %s'%(i,s));return redirect('/admin/solicitudes')
@app.route('/admin/solicitud/<int:i>/obligacion',methods=['POST'])
@need('apps')
def obl_new(i):
    p=q('select * from prices where id=? and active=1',(request.form.get('price','0'),),True)
    if not p: abort(400)
    q('insert into obligations(app_id,concept,period,amount_cents,due) values(?,?,?,?,?)',(i,p['concept'],p['period'],p['amount_cents'],p['due']));audit('obligación creada para solicitud %s'%i);return redirect('/admin/solicitudes')
@app.route('/admin/precios',methods=['GET','POST'])
@need('fin')
def prices():
    err=None
    if request.method=='POST':
        f=request.form
        try:
            a=cents(f.get('amount','')); 
            if f.get('id'):
                o=q('select * from prices where id=?',(f['id'],),True)
                if not o: abort(404)
                q('update prices set concept=?,period=?,amount_cents=?,due=?,active=? where id=?',(f['concept'],f['period'],a,f['due'],1 if f.get('active') else 0,o['id']))
                if o['amount_cents']!=a: q('insert into price_history(price_id,old_cents,new_cents,by_user,ts) values(?,?,?,?,?)',(o['id'],o['amount_cents'],a,session['email'],now()));notify(['owner'],'Cambio de precios','Se modificó un precio en el panel (%s).'%f['concept'])
            else: q('insert into prices(concept,period,amount_cents,due) values(?,?,?,?)',(f['concept'],f['period'],a,f['due']))
            audit('precio guardado: '+f['concept']);return redirect('/admin/precios')
        except ValueError as x: err=str(x)
    return render_template('adm.html',page='prices',rows=q('select * from prices'),hist=q('select h.*,p.concept from price_history h join prices p on p.id=h.price_id order by h.id desc limit 20'),err=err)
CRUD={'programas':('programs',['name','level','description','subjects']),'noticias':('news',['title','body','date'])}
@app.route('/admin/<sec>',methods=['GET','POST'])
@need('apps')
def crud(sec):
    if sec not in CRUD: abort(404)
    tb,cols=CRUD[sec]
    if request.method=='POST':
        if request.form.get('del'): q('delete from %s where id=?'%tb,(request.form['del'],))
        else: q('insert into %s(%s) values(%s)'%(tb,','.join(cols),','.join('?'*len(cols))),[request.form.get(c,'')[:4000] for c in cols])
        audit('%s modificado'%sec);return redirect('/admin/'+sec)
    return render_template('adm.html',page='crud',sec=sec,cols=cols,rows=q('select * from %s order by id desc'%tb))
@app.route('/admin/fotos',methods=['GET','POST'])
@need('apps')
def fotos():
    err=None
    if request.method=='POST':
        if request.form.get('del'):
            p=q('select * from photos where id=?',(request.form['del'],),True)
            if p:
                q('delete from files where name=?',(p['file'],))
                q('delete from photos where id=?',(p['id'],))
        else:
            try:
                fn=save_file(request.files['file'],{'jpg','jpeg','png','webp'},'media')
                q('insert into photos(title,description,category,file,sort) values(?,?,?,?,?)',(request.form.get('title','')[:120],request.form.get('description','')[:500],request.form.get('category','')[:60],fn,int(request.form.get('sort') or 0)));audit('foto subida')
            except (ValueError,KeyError) as x: err=str(x)
        if not err: return redirect('/admin/fotos')
    return render_template('adm.html',page='fotos',rows=q('select * from photos order by sort,id'),err=err)
@app.route('/admin/transferencias',methods=['GET','POST'])
@need('fin')
def transfers():
    if request.method=='POST':
        t=q("select * from transfers where id=? and status='pendiente'",(request.form.get('id'),),True)
        if not t: abort(404)
        o=q('select * from obligations where id=?',(t['obl_id'],),True);a=q('select * from applications where id=?',(o['app_id'],),True)
        if request.form.get('act')=='ok':
            q("update transfers set status='aprobada',reviewer=?,reviewed=? where id=?",(session['email'],now(),t['id']))
            q("update obligations set status='pagada' where id=?",(o['id'],))
            q('insert into payments(obl_id,method,amount_cents,currency,reference,status,confirmed_by,ts) values(?,?,?,?,?,?,?,?)',(o['id'],'transferencia',o['amount_cents'],o['currency'],t['reference'],'aprobado',session['email'],now()))
            enqueue(a['email'],'Transferencia aprobada','El colegio confirmó su pago de %s (%s).'%(money(o['amount_cents']),o['concept']))
        else:
            r=request.form.get('reason','').strip()
            if not r: abort(400)
            q("update transfers set status='rechazada',reason=?,reviewer=?,reviewed=? where id=?",(r,session['email'],now(),t['id']))
            enqueue(a['email'],'Transferencia rechazada','El colegio no pudo validar su transferencia. Motivo: %s'%r)
        audit('transferencia %s revisada'%t['id']);return redirect('/admin/transferencias')
    return render_template('adm.html',page='transf',rows=q('select t.*,o.concept,o.amount_cents,a.student from transfers t join obligations o on o.id=t.obl_id join applications a on a.id=o.app_id order by t.id desc'))
def money(c): return '$%.2f'%(c/100)
@app.route('/admin/comprobante/<int:i>')
@need('fin')
def receipt(i):
    t=q('select file from transfers where id=?',(i,),True)
    if not t or not t['file']: abort(404)
    r=q('select data,ctype from files where name=?',(t['file'],),True)
    if not r: abort(404)
    return Response(bytes(r['data']),mimetype={'pdf':'application/pdf','png':'image/png'}.get(r['ctype'],'image/jpeg'),headers={'Cache-Control':'private,no-store'})
@app.route('/admin/admins',methods=['GET','POST'])
@need('owner')
def admins():
    link=None
    if request.method=='POST':
        e=request.form.get('email','').strip().lower();r=request.form.get('role')
        if r not in PERMS or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$',e): abort(400)
        t=mk_token('invite',e,r,hours=72);link='%s/admin/token/%s'%(base_url(),t)
        enqueue(e,'Invitación al panel del colegio','Fue invitado como %s. Configure su acceso aquí (válido 72 h): %s'%(r,link));audit('invitación a '+e)
    return render_template('adm.html',page='admins',rows=q('select email,role,active from users'),link=link if not os.environ.get('SMTP_HOST') else None)
@app.route('/admin/ajustes',methods=['GET','POST'])
@need('owner')
def ajustes():
    K=['hero_title','hero_text','whatsapp','phone','email','address','hours','facebook','instagram','bank_info','bank_verified']
    if request.method=='POST':
        for k in K: q('insert into settings values(?,?) on conflict(k) do update set v=excluded.v',(k,request.form.get(k,'')[:1000]))
        audit('ajustes modificados');return redirect('/admin/ajustes')
    return render_template('adm.html',page='set',K=K)
@app.cli.command('create-admin')
def create_admin():
    import getpass;e=input('Correo: ').strip().lower();p=getpass.getpass('Contraseña (10+): ')
    assert len(p)>=10;q('insert into users(email,pw,role) values(?,?,?)',(e,generate_password_hash(p),'owner'));print('Administrador principal creado.')
init()
if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',8000)))
