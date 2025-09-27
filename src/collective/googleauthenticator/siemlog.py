# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import socket
import logging
import logging.handlers
from datetime import datetime

# ================== CONFIG ==================
SIEM_HOST = "172.16.243.20"
SIEM_PORT = 514  # UDP
APP_NAME  = "sottoservizi.gruppoiren.it"
SD_ID     = "gwAuth"            # OK senza PEN
MSGID     = "LOGIN"             # coerente con il tipo messaggio
LOGGER_NAME = "siem-rfc5424"
# ============================================


def rfc3339_utc():
    # RFC3339 con millisecondi e suffisso Z (UTC)
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_structured_data(sd_id, params):
    """
    Costruisce [SD-ID k="v" k2="v2"] con escaping minimo RFC5424 (\ " ])
    """
    def esc(v):
        s = v if isinstance(v, basestring) else str(v)
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
    pairs = " ".join('%s="%s"' % (k, esc(v)) for (k, v) in params.items() if v is not None)
    return "[%s %s]" % (sd_id, pairs) if pairs else "[%s]" % sd_id


def _client_ip_from_request(req):
    """
    IP sorgente dalla request Plone/Zope:
    - prende il PRIMO IP in X-Forwarded-For (client reale)
    - altrimenti usa REMOTE_ADDR
    """
    try:
        xff = req.get("HTTP_X_FORWARDED_FOR")
        if xff:
            # XFF può contenere "client, proxy1, proxy2"
            return xff.split(",")[0].strip()
        return req.get("REMOTE_ADDR")
    except Exception:
        return None


def _daily_file_path(prefix):
    """
    Path giornaliero nella cartella 'var' sotto la cwd del processo:
    <cwd>/var/<prefix>_YYYYMMDD.log
    """
    base_dir = os.path.join(os.environ.get("ZOPE_HOME", os.getcwd()),"audit_logging")
    if not os.path.isdir(base_dir):
        try:
            os.makedirs(base_dir)
        except Exception:
            pass
    day = datetime.utcnow().strftime("%Y%m%d")
    return os.path.join(base_dir, "%s_%s.log" % (prefix, day))


# ===== logger syslog dedicato (configurato UNA volta) =====
_logger = logging.getLogger(LOGGER_NAME)
if not _logger.handlers:
    h = logging.handlers.SysLogHandler(
        address=(SIEM_HOST, SIEM_PORT),
        socktype=socket.SOCK_DGRAM
    )
    # Invia SOLO il body RFC5424 che costruiamo (senza prefissi logging)
    h.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(h)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False
# ==========================================================


def send_login_event(tipo_evento, userid, request, message='-'):
    """
    Invia un evento RFC 5424 (UDP/514) con gli attributi MINIMI richiesti:
      - timestamp
      - tipo_evento ("LOGIN" o "LOGIN_FAILED")
      - indirizzo_sorgente (IP client da request)
      - userid
      - user agent
    E appende la stessa riga su un file locale giornaliero: var/auth_login_YYYYMMDD.log
    """
    try:
        ts = rfc3339_utc()
        ip_client = _client_ip_from_request(request) or "-"
        user_agent  = request.get("HTTP_USER_AGENT", "-")
        
        # SOLO i 3 attributi richiesti
        sd_params = {
            "timestamp": ts,
            "tipo_evento": tipo_evento,
            "indirizzo_sorgente": ip_client,
            "userid": userid,
            "user_agent": user_agent
        }

        # RFC5424 body (SENZA <PRI>): VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
        version  = "1"
        hostname = socket.gethostname().split(".")[0] or "host"
        procid   = str(os.getpid())
        sd       = build_structured_data(SD_ID, sd_params)
        msg      = message

        body = "%s %s %s %s %s %s %s %s" % (
            version, ts, hostname, APP_NAME, procid, MSGID, sd, msg
        )

        # ===== INVIO REALE =====
        _logger.info(body)  # SysLogHandler manda il datagramma UDP e aggiunge <PRI>
        # =======================

        # Scrittura locale (stessa riga con PRI esplicito per immediatezza)
        try:
            pri = "<134>"  # local0.info (16*8 + 6)
            wire = (pri + body).encode("utf-8")
            fpath = _daily_file_path("auth_login")
            fh = open(fpath, "ab")
            try:
                fh.write(wire + b"\n")
            finally:
                fh.close()
        except Exception:
            pass

        return True
    except Exception:
        return False
