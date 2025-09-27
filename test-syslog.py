# -*- coding: utf-8 -*-
import logging
import logging.handlers
import socket
import os
import getpass
from datetime import datetime

def rfc3339_utc():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"  # ms + Z

def build_structured_data(sd_id, params):
    # [sd_id key="val" key2="val2"]
    # Escape minimo per RFC5424: \, ", ]
    def esc(v):
        return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
    pairs = " ".join(['%s="%s"' % (k, esc(v)) for k, v in params.items() if v is not None])
    return "[%s %s]" % (sd_id, pairs) if pairs else "[%s]" % sd_id

def main():
    SERVER = ("172.16.243.20", 514) 
    HOST   = socket.gethostname().split(".")[0]
    APP    = "sottoservizi.gruppoiren.it"
    PROCID = str(os.getpid())
    MSGID  = "LOGIN"                       
    SD_ID  = "gwAuth"                  # enterprise SD-ID????
    
    current_user = getpass.getuser()
    ip_sorgente = socket.gethostbyname(socket.gethostname())
    
    #### qui che ci metto? vado a caso
    sd_params = {
        "timestamp": rfc3339_utc(),
        "event": "LOGIN",
        "action": "authenticate_test",
        "userid": current_user,
        "status_code": 200,
        "method": "POST",
        "url": "https://sottoservizi.gruppoiren.it/@@google_authenticator_token_form",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
        "ip": ip_sorgente
    }

    # Corpo RFC5424 (SENZA <PRI>): VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG
    version = "1"
    sd = build_structured_data(SD_ID, sd_params)
    msg = "-"  # niente MSG libero; tutto nei campi strutturati
    body = "%s %s %s %s %s %s %s %s" % (version, rfc3339_utc(), HOST, APP, PROCID, MSGID, sd, msg)

    # Logger + SysLogHandler UDP (il PRI verrà aggiunto automaticamente)
    logger = logging.getLogger("siem-rfc5424-test")
    handler = logging.handlers.SysLogHandler(address=SERVER, socktype=socket.SOCK_DGRAM)
    handler.setFormatter(logging.Formatter("%(message)s"))  # invia solo il body che abbiamo costruito
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # INVIO (severity INFO → PRI calcolato dall'handler)
    logger.info(body)

    print("Inviato RFC5424 a %s:%s" % SERVER)
    print(body)

if __name__ == "__main__":
    main()
