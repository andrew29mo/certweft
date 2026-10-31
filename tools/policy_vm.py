"""Root-only real CA policy and transient systemd credential verification."""
import sys,os,json,time,hashlib,html,pathlib,tempfile,subprocess,platform,secrets,shutil
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.core import run,validate
P=pathlib.Path(__file__).resolve().parents[1]
def hashes():
    return {str(p.relative_to(P)):hashlib.sha256(p.read_bytes()).hexdigest() for folder in ['certweft','tools','tests','policy'] for p in (P/folder).glob('*') if p.is_file()}

def main():
    os.umask(0o077)
    source=hashes();out=P/'evidence/policy.json';out.parent.mkdir(exist_ok=True)
    if out.exists():
        archive=P/'evidence/policy-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(d):
        text=json.dumps(d,indent=2);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>');out.write_text(text)
    publish({'passed':False,'status':'in_progress'})
    report={'passed':False,'cases':[],'scope':'real step-ca; transient systemd credential service; Linux VM', 'untested':['persistent daemon deployment','remote CA network','TPM/HSM','root compromise','orphan executor','power loss']}
    work=pathlib.Path(tempfile.mkdtemp(prefix='cw-policy-',dir='/var/tmp'));os.chmod(work,0o711)
    ca=None;account='cw-sign-'+secrets.token_hex(3);unit='cw-policy-'+secrets.token_hex(4)
    step=os.environ['CW_STEP'];stepca=os.environ['CW_CA'];secret=secrets.token_urlsafe(32);start=time.monotonic()
    def check(name,fn):
        t=time.monotonic()
        try:detail=fn()
        except Exception as e:
            report['cases'].append({'name':name,'passed':False,'error':type(e).__name__});raise
        report['cases'].append({'name':name,'passed':True,'seconds':time.monotonic()-t,'detail':detail})
    try:
        os.environ['STEPPATH']=str(work/'ca')
        (work/'ca-pass').write_text(secrets.token_urlsafe(32));os.chmod(work/'ca-pass',0o600)
        (work/'prov-pass').write_text(secret);os.chmod(work/'prov-pass',0o600)
        run([step,'ca','init','--name','Certweft restricted','--dns','localhost','--address','127.0.0.1:19091','--provisioner','exploration','--password-file',work/'ca-pass','--provisioner-password-file',work/'prov-pass'],20)
        cfgpath=work/'ca/config/ca.json';cfg=json.loads(cfgpath.read_text())
        prov=cfg['authority']['provisioners'][0]
        prov['claims']={'minTLSCertDuration':'5m','maxTLSCertDuration':'1h','defaultTLSCertDuration':'30m','disableRenewal':True,'enableSSHCA':False}
        prov['options']={'x509':{'templateFile':str(P/'policy/server.tpl')}}
        cfgpath.write_text(json.dumps(cfg));os.chmod(work/'ca',0o700)
        ca=subprocess.Popen([stepca,str(cfgpath),'--password-file',str(work/'ca-pass')],stdout=open(work/'ca.log','wb'),stderr=subprocess.STDOUT)
        root=work/'root.pem';shutil.copyfile(work/'ca/certs/root_ca.crt',root);os.chmod(root,0o644)
        for _ in range(60):
            try:run([step,'ca','health','--ca-url','https://localhost:19091','--root',root]);break
            except Exception:time.sleep(.1)
        else:raise RuntimeError('ca_start')
        def csr(name,curve='prime256v1',san='DNS:localhost',eku='serverAuth',extra=None):
            key=work/(name+'.key');request=work/(name+'.csr')
            if curve=='rsa':run(['openssl','genrsa','-out',key,'2048'])
            else:run(['openssl','ecparam','-name',curve,'-genkey','-noout','-out',key])
            args=['openssl','req','-new','-key',key,'-subj','/CN=localhost','-addext','subjectAltName='+san,'-addext','extendedKeyUsage='+eku,'-out',request]
            if extra:args+=['-addext',extra]
            run(args);return key,request
        def sign(name,request,password=None,duration=None,reason=None):
            target=work/(name+'.pem');offset=(work/'ca.log').stat().st_size
            args=[step,'ca','sign',request,target,'--ca-url','https://localhost:19091','--root',root,'--provisioner','exploration','--provisioner-password-file',password or work/'prov-pass']
            if duration:args+=['--not-after',duration]
            try:run(args,15)
            except subprocess.CalledProcessError as e:
                log=(work/'ca.log').read_text()[offset:]
                if reason:
                    assert reason in log,(name,'missing CA rejection reason')
                    assert 'status=4' in log,(name,'not CA HTTP 4xx')
                    assert not target.exists()
                    return {'ca_rejected':True,'reason':reason,'client_returncode':e.returncode}
                raise RuntimeError('unexpected_sign_failure') from None
            if reason:raise AssertionError('CA accepted forbidden CSR')
            return target
        key,request=csr('good')
        def allowed():
            from datetime import datetime
            cert=sign('good',request)
            validate(cert,key,root,'localhost')
            dates=run(['openssl','x509','-in',cert,'-dates','-noout']).decode().splitlines()
            times=[datetime.strptime(x.split('=',1)[1],'%b %d %H:%M:%S %Y %Z') for x in dates]
            duration=(times[1]-times[0]).total_seconds()
            assert 1800<=duration<=1860
            return {'verified':True,'actual_validity_seconds':duration,'requested_default_seconds':1800,'allowed_backdate_seconds':60}
        check('allowed_certificate',allowed)
        for name,kwargs,reason in [('wrong_name',{'san':'DNS:wrong.invalid'},'CW_NAME'),('extra_name',{'san':'DNS:localhost,DNS:wrong.invalid'},'CW_NAME'),('ip_san',{'san':'DNS:localhost,IP:127.0.0.1'},'CW_NAME'),('client_auth',{'eku':'serverAuth,clientAuth'},'CW_EKU'),('p384',{'curve':'secp384r1'},'CW_KEY'),('rsa',{'curve':'rsa'},'CW_KEY'),('ca_true',{'extra':'basicConstraints=critical,CA:TRUE'},'CW_CA')]:
            _,req=csr(name,**kwargs);check(name,lambda n=name,r=req,why=reason:sign(n,r,reason=why))
        check('excess_duration',lambda:sign('long',request,duration='2h',reason='maximum'))
        check('insufficient_duration',lambda:sign('short',request,duration='1m',reason='minimum'))
        # Actual systemd credentials, separate non-login signer identity, no CA key access.
        run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin',account])
        import pwd
        uid=pwd.getpwnam(account).pw_uid;gid=pwd.getpwnam(account).pw_gid
        client=work/'client';client.mkdir(mode=0o700);os.chown(client,uid,gid)
        shutil.copyfile(key,client/'key.pem');os.chown(client/'key.pem',uid,gid);os.chmod(client/'key.pem',0o600)
        def delivered():
            command=['systemd-run','--unit',unit,'--wait','--collect','--pipe','-p','User='+account,'-p','NoNewPrivileges=yes','-p','ProtectSystem=strict','-p','ProtectHome=read-only','-p','ReadWritePaths='+str(client),'-p','LoadCredential=provisioner-password:'+str(work/'prov-pass'),'-p','Environment=STEPPATH='+str(client/'step'),'-p','Environment=PYTHONPATH='+str(P),'python3','-m','certweft.ca',step,'https://localhost:19091',root,client/'key.pem',client/'cert.pem']
            try:output=run(command,25)
            except subprocess.CalledProcessError as e:
                (work/'service-error').write_bytes(e.stdout+b'\n'+e.stderr);os.chmod(work/'service-error',0o600)
                raise
            assert secret.encode() not in output and secret not in ' '.join(map(str,command))
            validate(client/'cert.pem',client/'key.pem',root,'localhost')
            journal=run(['journalctl','-u',unit,'--no-pager'])
            assert secret.encode() not in journal
            return 'non-login signer issued through LoadCredential; no secret contents in argv or captured output'
        check('systemd_credential_delivery',delivered)
        def denied():
            for path in [work/'prov-pass',work/'ca/secrets/root_ca_key',work/'ca/secrets/intermediate_ca_key',work/'ca.log']:
                for identity in ['nobody',account]:
                    code=subprocess.run(['runuser','-u',identity,'--','test','-r',str(path)]).returncode
                    assert code!=0
            assert subprocess.run(['runuser','-u','nobody','--','test','-r',str(client/'key.pem')]).returncode!=0
            return 'nobody and signer denied source password, CA private keys and raw CA logs; nobody denied service key'
        check('credential_source_isolation',denied)
        report['passed']=True
    except Exception as e:
        report['error']=type(e).__name__
        # Error details remain local: commands can contain private file paths.
        import traceback;traceback.print_exc()
    finally:
        if ca:
            ca.terminate()
            try:ca.wait(5)
            except subprocess.TimeoutExpired:ca.kill();ca.wait();report['cleanup_error']='ca_forced'
        subprocess.run(['systemctl','stop',unit],capture_output=True)
        subprocess.run(['userdel',account],capture_output=True)
        remaining=subprocess.run(['id',account],capture_output=True).returncode==0
        active=subprocess.run(['systemctl','is-active',unit],capture_output=True).returncode==0
        report['cleanup_verified']=not remaining and not active and (ca is None or ca.poll() is not None)
        if not report['cleanup_verified']:report['cleanup_error']='owned_resources_remain'
        report['source_sha256']=source;report['source_unchanged']=source==hashes()
        report['versions']={'step':run([step,'version']).decode().splitlines()[0],'step_ca':run([stepca,'version']).decode().splitlines()[0],'python':platform.python_version()}
        report['elapsed_seconds']=time.monotonic()-start
        report['passed']=report['passed'] and report['source_unchanged'] and not report.get('cleanup_error')
        text=json.dumps(report);assert secret not in text
        publish(report);print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}))
    return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
