"""Sanitized storage diagnostics; no exception messages or private paths."""
import errno,sqlite3
PREFIXES=('SQLITE_FULL','SQLITE_READONLY','SQLITE_IOERR','SQLITE_CORRUPT','SQLITE_NOTADB','SQLITE_CANTOPEN')
def detail(error):
    if isinstance(error,dict):return {'sqlite_error':error.get('sqlite_error'),'errno':error.get('errno')}
    return {'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)}
def failed(error):
    d=detail(error)
    return bool(d['sqlite_error'] and d['sqlite_error'].startswith(PREFIXES)) or d['errno'] in {errno.ENOSPC,errno.EROFS,errno.EIO,errno.EDQUOT}
