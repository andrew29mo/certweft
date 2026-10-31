"""Fixed Smallstep CSR reissuance adapter; no implicit reload hooks."""
from pathlib import Path
from .core import run,Rejected

def reissue(step,ca_url,root,key,password,destination):
    destination=Path(destination)
    if destination.exists():raise Rejected('output_exists')
    csr=destination.with_suffix('.csr')
    if csr.exists():raise Rejected('csr_exists')
    run(['openssl','req','-new','-key',key,'-subj','/CN=localhost',
         '-addext','subjectAltName=DNS:localhost','-out',csr])
    run([step,'ca','sign',csr,destination,'--ca-url',ca_url,'--root',root,
         '--provisioner','exploration','--provisioner-password-file',password],15)
    return 'real CA same-key CSR reissuance'
