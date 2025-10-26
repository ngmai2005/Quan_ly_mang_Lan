import os
from datetime import datetime
import subprocess

ACTIONS_LOG = "data/actions.log"
BLOCKED_FILE = "blocked_ip.txt"

def log_action(action, ip, user="admin"):
    """Ghi actions.log: [timestamp] user ACTION IP"""
    os.makedirs(os.path.dirname(ACTIONS_LOG) or ".", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {user} {action} {ip}\n"
    with open(ACTIONS_LOG, "a", encoding="utf-8") as f:
        f.write(line)

def block_ip_system(ip, simulate=True):
    """Chặn IP trên hệ thống. Nếu simulate=True sẽ không thực thi firewall, chỉ ghi file blocked_ip.txt.
       Trả về dict {ok:bool, msg:str}"""
    try:
        # ghi file blocked list
        with open(BLOCKED_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ip}\n")
    except Exception as e:
        return {"ok": False, "msg": str(e)}

    if simulate:
        log_action("SIMULATED_BLOCK", ip)
        return {"ok": True, "msg": "Simulated block (no system change)"}
    # thực thi lệnh Windows Firewall (yêu cầu admin)
    try:
        cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
               f'name=Block_{ip}', 'dir=in', 'action=block', f'remoteip={ip}']
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            log_action("BLOCK", ip)
            return {"ok": True, "msg": "Blocked via netsh"}
        else:
            log_action("BLOCK_FAILED", ip)
            return {"ok": False, "msg": proc.stderr.strip() or proc.stdout.strip()}
    except Exception as e:
        log_action("BLOCK_ERROR", ip)
        return {"ok": False, "msg": str(e)}

def unblock_ip_system(ip, simulate=True):
    """Bỏ chặn IP: xóa khỏi blocked_ip.txt và chạy netsh delete rule"""
    # xóa khỏi blocked list
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and l.strip() != ip]
            with open(BLOCKED_FILE, "w", encoding="utf-8") as f:
                if lines:
                    f.write("\n".join(lines) + "\n")
    except Exception as e:
        return {"ok": False, "msg": str(e)}

    if simulate:
        log_action("SIMULATED_UNBLOCK", ip)
        return {"ok": True, "msg": "Simulated unblock (no system change)"}

    # thực thi netsh xóa rule
    try:
        cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name=Block_{ip}']
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            log_action("UNBLOCK", ip)
            return {"ok": True, "msg": "Unblocked via netsh"}
        else:
            log_action("UNBLOCK_FAILED", ip)
            return {"ok": False, "msg": proc.stderr.strip() or proc.stdout.strip()}
    except Exception as e:
        log_action("UNBLOCK_ERROR", ip)
        return {"ok": False, "msg": str(e)}
