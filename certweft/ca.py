"""Fixed Smallstep CSR reissuance adapter; no implicit reload hooks."""
from pathlib import Path
from .core import run,Rejected

def reissue(step,ca_url,root,key,password,destination):
    destination=Path(destination)
    if destination.exists():raise Rejected('output_exists')
    csr=destination.with_suffix('.csr')
    if csr.exists():raise Rejected('csr_exists')
    run(['openssl','req','-new','-key',key,'-subj','/CN=localhost',
         '-addext','subjectAltName=DNS:localhost','-addext','extendedKeyUsage=serverAuth','-out',csr])
    run([step,'ca','sign',csr,destination,'--ca-url',ca_url,'--root',root,
         '--provisioner','exploration','--provisioner-password-file',password],15)
    return 'real CA same-key CSR reissuance'


def reissue_credential(step,ca_url,root,key,destination):
    """Read only the systemd-delivered credential path; never place secret in argv."""
    import os,stat
    directory=os.environ.get('CREDENTIALS_DIRECTORY')
    if not directory:raise Rejected('credential_missing')
    password=Path(directory)/'provisioner-password'
    st=password.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_mode & 0o027
        or st.st_mode & 0o040 and st.st_gid!=0
        or st.st_uid not in {0,os.geteuid()}):raise Rejected('credential_permissions')
    return reissue(step,ca_url,root,key,password,destination)

if __name__=='__main__':
    import sys
    # No secret contents are printed, including on failure.
    try:reissue_credential(*sys.argv[1:]);print('issued')
    except Exception as e:print('issuance_failed:'+type(e).__name__,file=sys.stderr);sys.exit(1)
