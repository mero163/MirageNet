import copy
import json
import os
import posixpath
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_FILESYSTEM: Dict[str, Any] = {
    "/": {
        "home": {
            "admin": {
                "notes.txt": (
                    "TODO:\n"
                    "- Rotate production DB passwords on Friday\n"
                    "- Check /opt/company_data/ for Q4 payroll export\n"
                    "- Remind HR to remove old VPN tokens\n"
                ),
                "deploy.sh": "#!/bin/bash\nrsync -avz /var/www/html/ prod-app-02:/var/www/\n",
                ".bash_history": (
                    "cd /opt/company_data\n"
                    "ls -la\n"
                    "cat aws_credentials.env\n"
                    "systemctl status nginx\n"
                    "exit\n"
                ),
            }
        },
        "opt": {
            "company_data": {
                "salaries_2026.csv": (
                    "# CANARY_TOKEN: CNRY-FIN-9941-X8A\n"
                    "emp_id,name,department,salary_usd,iban\n"
                    "1001,Ahmed Hassan,Engineering,14500,EG380019000500000000123456\n"
                    "1002,Sara Mohamed,Finance,16200,EG380019000500000000789012\n"
                    "1003,Omar Khaled,Executive,24000,EG380019000500000000345678\n"
                    "1004,Nourhan Ali,Security,15800,EG380019000500000000901234\n"
                ),
                "aws_credentials.env": (
                    "# CANARY_TOKEN: CNRY-AWS-7720-K3Z\n"
                    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7MIRAGE\n"
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYMIRAGEKEY\n"
                    "AWS_DEFAULT_REGION=eu-central-1\n"
                    "S3_BACKUP_BUCKET=s3://corp-confidential-backups-2026\n"
                ),
                "db_backup.sql": (
                    "-- CANARY_TOKEN: CNRY-SQL-4410-M9P\n"
                    "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n"
                    "INSERT INTO `admin_users` VALUES (1,'superadmin','$2b$12$KIX9FAKEHASHVALUE0001','admin@corp-internal.local');\n"
                    "INSERT INTO `admin_users` VALUES (2,'cfo_office','$2b$12$KIX9FAKEHASHVALUE0002','cfo@corp-internal.local');\n"
                ),
            }
        },
        "var": {
            "www": {
                "html": {
                    "config.php": (
                        "<?php\n"
                        "// CANARY_TOKEN: CNRY-WEB-5512-Q1W\n"
                        "define('DB_HOST', '10.20.0.14');\n"
                        "define('DB_USER', 'webapp_prod');\n"
                        "define('DB_PASS', 'Pr0d#M1rag3!2026');\n"
                        "define('DB_NAME', 'corp_portal');\n"
                        "?>\n"
                    ),
                    "index.html": "<html><body><h1>Corp Internal Portal v4.2</h1></body></html>\n",
                }
            },
            "log": {
                "auth.log": (
                    "Nov 27 21:10:02 corp-srv sshd[1421]: Accepted publickey for admin from 10.0.1.5 port 51234\n"
                    "Nov 27 21:14:19 corp-srv sshd[1890]: Failed password for root from 185.220.101.42 port 44122\n"
                )
            },
        },
        "etc": {
            "passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "admin:x:1000:1000:System Admin:/home/admin:/bin/bash\n"
                "mysql:x:112:118:MySQL Server:/nonexistent:/bin/false\n"
            ),
            "hosts": (
                "127.0.0.1 localhost\n"
                "10.20.0.10 corp-app-01\n"
                "10.20.0.14 corp-db-master\n"
                "10.20.0.25 corp-finance-vault\n"
            ),
        },
    }
}


class IllusionSessionState:
    """Maintains stateful virtual filesystem and environment per trapped attacker."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.fs = copy.deepcopy(DEFAULT_FILESYSTEM["/"])
        self.cwd = "/home/admin"
        self.user = "admin"
        self.hostname = "corp-prod-srv01"
        self.history: List[str] = []
        self.llm_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
        self.llm_model: str = os.getenv("MIRAGE_LLM_MODEL", "gpt-4o-mini")

    def _resolve_node(self, path: str) -> Tuple[Optional[Any], str]:
        abs_path = posixpath.normpath(
            path if path.startswith("/") else posixpath.join(self.cwd, path)
        )
        if abs_path == "/":
            return self.fs, "/"
        parts = [p for p in abs_path.split("/") if p]
        curr: Any = self.fs
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return None, abs_path
        return curr, abs_path

    def _resolve_parent(self, path: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
        abs_path = posixpath.normpath(
            path if path.startswith("/") else posixpath.join(self.cwd, path)
        )
        parent_path = posixpath.dirname(abs_path)
        name = posixpath.basename(abs_path)
        parent_node, _ = self._resolve_node(parent_path)
        if isinstance(parent_node, dict):
            return parent_node, name, abs_path
        return None, name, abs_path

    def _call_llm_illusion(self, command: str) -> Optional[str]:
        """Optional live LLM fallback for arbitrary commands if API key is configured."""
        if not self.llm_api_key:
            return None
        try:
            prompt = (
                f"You are an Ubuntu 24.04 corporate production server named {self.hostname} "
                f"acting as an active cybersecurity deception honeypot. "
                f"Current user: {self.user}, current directory: {self.cwd}. "
                f"Recent commands: {self.history[-5:]}. "
                f"Respond ONLY with the realistic terminal stdout/stderr for the command: `{command}`. "
                f"Never break character. Keep output concise and realistic."
            )
            body = json.dumps(
                {
                    "model": self.llm_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 280,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.llm_api_key}",
                },
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"].strip()
        except Exception:
            return None

    def execute(self, raw_cmd: str) -> Tuple[str, str]:
        """Execute a command inside the stateful illusion room and return (output, new_cwd)."""
        cmd = raw_cmd.strip()
        if not cmd:
            return "", self.cwd

        self.history.append(cmd)
        parts = cmd.split()
        base = parts[0]
        args = parts[1:]

        if base == "pwd":
            return self.cwd, self.cwd

        if base == "whoami":
            return self.user, self.cwd

        if base == "id":
            if self.user == "root":
                return "uid=0(root) gid=0(root) groups=0(root)", self.cwd
            return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo),33(www-data)", self.cwd

        if base == "hostname":
            return self.hostname, self.cwd

        if base == "uname":
            return "Linux corp-prod-srv01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux", self.cwd

        if base == "cd":
            target = args[0] if args else "/home/admin"
            node, abs_path = self._resolve_node(target)
            if isinstance(node, dict):
                self.cwd = abs_path
                return "", self.cwd
            elif node is not None:
                return f"bash: cd: {target}: Not a directory", self.cwd
            return f"bash: cd: {target}: No such file or directory", self.cwd

        if base in ("ls", "ll", "dir"):
            show_all = "-a" in args or "-la" in args or "-al" in args or base == "ll"
            long_fmt = "-l" in args or "-la" in args or "-al" in args or base == "ll"
            path_args = [a for a in args if not a.startswith("-")]
            target = path_args[0] if path_args else self.cwd
            node, _ = self._resolve_node(target)
            if node is None:
                return f"ls: cannot access '{target}': No such file or directory", self.cwd
            if isinstance(node, str):
                return target, self.cwd
            entries = sorted(node.keys())
            if not show_all:
                entries = [e for e in entries if not e.startswith(".")]
            if not long_fmt:
                return "  ".join(entries), self.cwd
            lines = [f"total {len(entries) * 4}"]
            for e in entries:
                is_dir = isinstance(node[e], dict)
                perms = "drwxr-xr-x" if is_dir else "-rw-r-----"
                size = 4096 if is_dir else len(str(node[e]))
                lines.append(f"{perms} 1 {self.user} corp {size:>6} Nov 27 21:00 {e}")
            return "\n".join(lines), self.cwd

        if base in ("cat", "head", "tail", "more", "less"):
            if not args:
                return f"{base}: missing file operand", self.cwd
            target = args[-1]
            node, _ = self._resolve_node(target)
            if node is None:
                return f"{base}: {target}: No such file or directory", self.cwd
            if isinstance(node, dict):
                return f"{base}: {target}: Is a directory", self.cwd
            return str(node).rstrip("\n"), self.cwd

        if base == "mkdir":
            if not args:
                return "mkdir: missing operand", self.cwd
            parent, name, _ = self._resolve_parent(args[0])
            if parent is None:
                return f"mkdir: cannot create directory '{args[0]}': No such file or directory", self.cwd
            if name in parent:
                return f"mkdir: cannot create directory '{args[0]}': File exists", self.cwd
            parent[name] = {}
            return "", self.cwd

        if base == "touch":
            if not args:
                return "touch: missing file operand", self.cwd
            parent, name, _ = self._resolve_parent(args[0])
            if parent is None:
                return f"touch: cannot touch '{args[0]}': No such file or directory", self.cwd
            parent.setdefault(name, "")
            return "", self.cwd

        if base == "rm":
            path_args = [a for a in args if not a.startswith("-")]
            if not path_args:
                return "rm: missing operand", self.cwd
            parent, name, _ = self._resolve_parent(path_args[0])
            if parent is None or name not in parent:
                return f"rm: cannot remove '{path_args[0]}': No such file or directory", self.cwd
            del parent[name]
            return "", self.cwd

        if base == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "  412 ?        00:00:04 nginx: master process\n"
                "  589 ?        00:01:12 mysqld --daemonize\n"
                "  801 ?        00:00:02 python3 /opt/internal_api/app.py\n"
                " 1421 ?        00:00:00 sshd: admin@pts/0"
            ), self.cwd

        if base in ("netstat", "ss"):
            return (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
                "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
                "tcp        0      0 10.20.0.10:8080         0.0.0.0:*               LISTEN"
            ), self.cwd

        if base in ("ifconfig", "ip"):
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.20.0.10  netmask 255.255.255.0  broadcast 10.20.0.255\n"
                "        ether 02:42:ac:14:00:0a  txqueuelen 1000  (Ethernet)"
            ), self.cwd

        if base == "env":
            return (
                "USER=admin\n"
                "HOME=/home/admin\n"
                "SHELL=/bin/bash\n"
                "DB_INTERNAL_HOST=10.20.0.14\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ), self.cwd

        if base == "history":
            return "\n".join(f"  {i+1}  {h}" for i, h in enumerate(self.history)), self.cwd

        if base == "find":
            results = []
            def walk(node: Any, prefix: str) -> None:
                if isinstance(node, dict):
                    for k, v in node.items():
                        p = f"{prefix}/{k}" if prefix != "/" else f"/{k}"
                        results.append(p)
                        walk(v, p)
            walk(self.fs, "/")
            return "\n".join(results[:25]), self.cwd

        if base == "sudo":
            if args and args[0] in ("su", "-i", "bash"):
                self.user = "root"
                return "[sudo] password for admin: \nroot@corp-prod-srv01:~# (simulated privilege escalation)", self.cwd
            return "Sorry, try again.", self.cwd

        if base in ("curl", "wget"):
            return (
                f"--2026-11-27 21:40:12--  {args[-1] if args else 'http://evil.c2/payload'}\n"
                "Connecting... connected.\n"
                "HTTP request sent, awaiting response... 200 OK\n"
                "Length: 14208 (14K) [application/octet-stream]\n"
                "Saving to: 'payload.bin' [100%]"
            ), self.cwd

        if base == "nmap":
            return (
                "Starting Nmap 7.94 ( https://nmap.org )\n"
                "Nmap scan report for 10.20.0.14\n"
                "PORT     STATE SERVICE\n"
                "22/tcp   open  ssh\n"
                "3306/tcp open  mysql\n"
                "8080/tcp open  http-proxy\n"
                "Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds"
            ), self.cwd

        if base == "help":
            return (
                "Available illusion shell commands: ls, ll, cd, pwd, cat, find, whoami, id, "
                "uname, ps, netstat, ifconfig, env, history, sudo, curl, wget, nmap, mkdir, touch, rm"
            ), self.cwd

        # Try optional live LLM fallback if configured
        llm_reply = self._call_llm_illusion(cmd)
        if llm_reply:
            return llm_reply, self.cwd

        return f"bash: {base}: command not found", self.cwd


# In-memory active illusion sessions
_SESSIONS: Dict[str, IllusionSessionState] = {}


def get_or_create_illusion_session(session_id: str) -> IllusionSessionState:
    if session_id not in _SESSIONS:
        _SESSIONS[session_id] = IllusionSessionState(session_id)
    return _SESSIONS[session_id]
