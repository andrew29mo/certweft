"""Linux boot-scoped persistent budgets; no wall-clock deadline resurrection."""
import contextvars,time
from contextlib import contextmanager
from pathlib import Path
class Expired(RuntimeError):pass
CURRENT=contextvars.ContextVar('certweft_deadline',default=None)
def now_ns():return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def create(seconds):
    now=now_ns()
    return {'version':1,'boot_id':boot_id(),'accepted_boot_ns':now,'expires_boot_ns':now+seconds*1_000_000_000,'accepted_wall_ns':time.time_ns(),'seconds':seconds}
def clock_valid(record):
    if record['version']!=1 or record['boot_id']!=boot_id():raise Expired('boot_changed')
    elapsed=now_ns()-record['accepted_boot_ns']
    if elapsed<0:raise Expired('clock_regression')
    if abs((time.time_ns()-record['accepted_wall_ns'])-elapsed)>5_000_000_000:raise Expired('wall_clock_anomaly')
def remaining(record):
    if record is None:return None
    clock_valid(record)
    left=(record['expires_boot_ns']-now_ns())/1_000_000_000
    if left<=0:raise Expired('deadline_expired')
    return left
def check():return remaining(CURRENT.get())
def timeout(limit):
    left=check();return limit if left is None else min(limit,left)
@contextmanager
def use(record):
    token=CURRENT.set(record)
    try:check();yield
    finally:CURRENT.reset(token)
