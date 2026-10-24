import os,tempfile,unittest,re,io
os.environ['DATA_DIR']=tempfile.mkdtemp()
import app as A
from werkzeug.security import generate_password_hash
class T(unittest.TestCase):
    @classmethod
    def setUpClass(c):
        with A.app.app_context():
            for e,r in(('own@x.com','owner'),('sec@x.com','secretaria'),('fin@x.com','finanzas')): A.q('insert into users(email,pw,role) values(?,?,?)',(e,generate_password_hash('claveSegura123'),r))
    def cl(s): return A.app.test_client()
    def tok(s,c):
        c.get('/');
        with c.session_transaction() as x: return x['csrf']
    def login(s,e,p='claveSegura123'):
        c=s.cl();t=s.tok(c);r=c.post('/admin',data={'email':e,'password':p,'csrf':t});return c,s.tok(c),r
    def test_01_pre(s):
        c=s.cl();t=s.tok(c)
        s.assertEqual(c.post('/preinscripcion',data={'student':'Ana Perez'}).status_code,400)  # sin csrf
        r=c.post('/preinscripcion',data={'csrf':t,'student':'Ana Perez','birth':'2015-03-02','level':'Básica','guardian':'Luis Perez','email':'L@x.com','phone':'0991234567','consent':'1'})
        s.assertEqual(r.status_code,302)
        with A.app.app_context():
            s.assertEqual(A.q('select count(*) c from applications',one=True)['c'],1)
            s.assertEqual(A.q("select count(*) c from outbox where to_addr='own@x.com'",one=True)['c'],1)
        s.assertEqual(c.post('/preinscripcion',data={'csrf':t,'student':'A'}).status_code,400)
    def test_02_authz(s):
        s.assertEqual(s.cl().get('/admin/panel').status_code,302)
        c,t,_=s.login('sec@x.com');s.assertEqual(c.get('/admin/solicitudes').status_code,200);s.assertEqual(c.get('/admin/precios').status_code,403);s.assertEqual(c.get('/admin/admins').status_code,403)
        c,t,_=s.login('fin@x.com');s.assertEqual(c.get('/admin/solicitudes').status_code,403)
    def test_03_prices_flow(s):
        c,t,_=s.login('own@x.com')
        c.post('/admin/precios',data={'csrf':t,'concept':'Matrícula','period':'2026-2027','amount':'120.50','due':'2000-01-01'})
        with A.app.app_context():
            p=A.q('select * from prices',one=True);s.assertEqual(p['amount_cents'],12050)
            a=A.q('select * from applications',one=True)
        c.post('/admin/solicitud/%d/obligacion'%a['id'],data={'csrf':t,'price':p['id']})
        c.post('/admin/precios',data={'csrf':t,'id':p['id'],'concept':'Matrícula','period':'2026-2027','amount':'200','due':'2000-01-01','active':'on'})
        with A.app.app_context():
            s.assertEqual(A.q('select amount_cents from obligations',one=True)[0],12050)  # no retroactivo
            s.assertEqual(A.q('select count(*) from price_history',one=True)[0],1)
            o=A.q('select id from obligations',one=True)['id']
        pc=s.cl();pt=s.tok(pc)
        bad=pc.post('/transferencia',data={'csrf':pt,'code':a['code'],'email':'otro@x.com','obl':o,'reference':'ABC123'})
        s.assertIn(b'incorrectos',bad.data)
        pdf=(io.BytesIO(b'%PDF-1.4 test'),'c.pdf')
        r=pc.post('/transferencia',data={'csrf':pt,'code':a['code'],'email':'l@x.com','obl':o,'reference':'ABC123','file':pdf},content_type='multipart/form-data');s.assertIn(b'pendiente de revisi',r.data)
        fake=(io.BytesIO(b'MZ evil'),'x.pdf');r=pc.post('/transferencia',data={'csrf':pt,'code':a['code'],'email':'l@x.com','obl':o,'reference':'ZZZ999','file':fake},content_type='multipart/form-data');s.assertNotIn(b'Recibimos',r.data)
        s.assertEqual(pc.get('/admin/comprobante/1').status_code,302)  # privado
        fc,ft,_=s.login('fin@x.com')
        with A.app.app_context(): s.assertEqual(A.q('select status from obligations',one=True)[0],'pendiente')
        s.assertEqual(fc.get('/admin/comprobante/1').status_code,200)
        fc.post('/admin/transferencias',data={'csrf':ft,'id':1,'act':'ok'})
        with A.app.app_context():
            s.assertEqual(A.q('select status from obligations',one=True)[0],'pagada');s.assertEqual(A.q('select sum(amount_cents) from payments',one=True)[0],12050)
    def test_04_login_throttle_reset(s):
        c=s.cl();t=s.tok(c)
        for _ in range(5): c.post('/admin',data={'email':'own@x.com','password':'mal','csrf':t})
        s.assertEqual(c.post('/admin',data={'email':'own@x.com','password':'claveSegura123','csrf':t}).status_code,429)
        with A.app.app_context(): A.q('delete from attempts')
        c.post('/admin/olvide',data={'email':'sec@x.com','csrf':t})
        with A.app.app_context(): b=A.q("select body from outbox where subject like 'Restablecer%' and to_addr='sec@x.com'",one=True)['body']
        tk=re.search(r'token/(\S+)',b).group(1)
        s.assertEqual(c.post('/admin/token/'+tk,data={'csrf':t,'password':'nuevaClave12345','password2':'nuevaClave12345'}).status_code,302)
        s.assertEqual(c.post('/admin/token/'+tk,data={'csrf':t,'password':'otraClave12345','password2':'otraClave12345'}).status_code,404)  # un solo uso
        s.assertEqual(s.login('sec@x.com','nuevaClave12345')[2].status_code,302)
    def test_05_invite(s):
        c,t,_=s.login('own@x.com');c.post('/admin/admins',data={'csrf':t,'email':'nuevo@x.com','role':'secretaria'})
        with A.app.app_context(): b=A.q("select body from outbox where to_addr='nuevo@x.com'",one=True)['body']
        tk=re.search(r'token/(\S+)',b).group(1).rstrip('.')
        s.assertEqual(s.login('nuevo@x.com','x')[2].status_code,200)  # sin invitación no entra
        n=s.cl();nt=s.tok(n);n.post('/admin/token/'+tk,data={'csrf':nt,'password':'claveInvitado12','password2':'claveInvitado12'})
        s.assertEqual(s.login('nuevo@x.com','claveInvitado12')[2].status_code,302)
    def test_06_public(s):
        r=s.cl().get('/');s.assertEqual(r.status_code,200);s.assertNotIn(b'pr\xc3\xb3ximamente',r.data)
unittest.main(verbosity=2)
