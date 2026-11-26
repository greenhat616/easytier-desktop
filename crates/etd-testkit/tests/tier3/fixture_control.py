from contextlib import ExitStack
from pathlib import Path
import os
import tempfile
import time
from service import require_runner
from inventory import capture, WINDOWS_POLICY_GROUPS
import foreign

require_runner()
group=os.environ["GROUP"]
def diff(label, a, b):
    print(group,label,"native delta count",len(a.delta(b)),flush=True)
    for g in sorted(WINDOWS_POLICY_GROUPS):
        old,new=a.policy_filters[g],b.policy_filters[g]
        print(group,label,g,"missing",(old-new).total(),"extra",(new-old).total(),flush=True)
    for k in sorted(a.delta(b)):
        if k[0]=="registry" and k[1].rsplit(chr(92),1)[-1] in ("Dhcpv6Iaid","Dhcpv6State"):
            print(group,label,*k,"added" if k not in a.rows else "changed",flush=True)

with tempfile.TemporaryDirectory() as d:
    root=Path(d)
    base=capture(root,[])
    with ExitStack() as stack:
        began=time.monotonic()
        if group=="fixture":
            stack.enter_context(foreign.windows())
        time.sleep(max(0,45-(time.monotonic()-began)))
        with_fixture=capture(root,[])
        diff("active",base,with_fixture)
    end=time.monotonic()
    for seconds in (0,30,90,180):
        time.sleep(max(0,end+seconds-time.monotonic()))
        diff(f"removed-{seconds}",base,capture(root,[]))
