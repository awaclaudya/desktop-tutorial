import sys
import KSR as KSR

# =========================================================
# CONFIGURAÇÃO
# =========================================================
redial_lists = {}
OPERATOR_DOMAIN = "acme.operador"
MAX_RETRIES = 3      
TEST_TIMEOUT = 36000  

# =========================================================
# HELPERS
# =========================================================
def get_aor():
    return f"sip:{KSR.pv.get('$fU')}@{KSR.pv.get('$fd')}"

def check_security():
    if KSR.pv.get("$fd") != OPERATOR_DOMAIN:
        KSR.info(f"[SEC] Denied: {KSR.pv.get('$fd')}\n")
        KSR.sl.send_reply(403, "Forbidden - acme.operador only")
        return False
    return True

# =========================================================
# KAMAILIO CORE
# =========================================================
def mod_init():
    return kamailio()

class kamailio:
    def child_init(self, rank): return 0

    # --- LÓGICA DE REDIAL ---
    def try_next_redial(self):
        # Ler estado
        targets = (KSR.pv.get("$avp(redial_targets)") or "").split(",")
        idx = int(KSR.pv.get("$avp(current_idx)") or 0)
        retries = int(KSR.pv.get("$avp(retries)") or 0)

        if not targets or not targets[0] or retries <= 0:
            KSR.info("[REDIAL] Stop: No retries or empty list.\n")
            KSR.sl.send_reply(480, "Redial Given Up")
            return 1

        # Selecionar alvo (Loop Infinito usando Modulo)
        target = targets[idx % len(targets)]
        KSR.info(f"[REDIAL] Retry {retries} left. Target: {target}\n")

        # Configurar envio
        KSR.pv.sets("$ru", target)
        KSR.pv.sets("$avp(current_idx)", str(idx + 1))
        
        # Verificar se está ONLINE (Lookup)
        if KSR.registrar.lookup("location") != 1:
            KSR.info(f"[REDIAL] {target} Offline. Skipping...\n")
            return self.try_next_redial() # Recursão para o próximo

        # Preparar falha e enviar
        KSR.pv.sets("$avp(retries)", str(retries - 1))
        KSR.tm.t_on_failure("failure_REDIAL")
        KSR.tm.t_set_fr(TEST_TIMEOUT, TEST_TIMEOUT)
        KSR.tm.t_relay()
        return 1

    # --- ROTEAMENTO DE PEDIDOS ---
    def ksr_request_route(self, msg):
        if not check_security(): return 1

        sender = get_aor()

        # 1. REGISTO
        if KSR.is_method("REGISTER"):
            # Obter expires (Header ou Contact param ou default 3600)
            exp = int(KSR.pv.get("$hdr(Expires)") or KSR.pv.get("$(ct{param.value,expires})") or 3600)
            
            if exp == 0:
                redial_lists.pop(sender, None) # Remove se existir
                KSR.info(f"[REG] {sender} Deregistered.\n")
            elif sender not in redial_lists:
                redial_lists[sender] = [] # Inicializa
                KSR.info(f"[REG] {sender} Registered.\n")
            
            KSR.registrar.save("location", 0)
            return 1

        # 2. CONFIGURAÇÃO (MESSAGE)
        if KSR.is_method("MESSAGE"):

            if KSR.pv.get("$rU") == "validar":

            if KSR.pv.get("$rU") == "redial":
                body = str(KSR.pv.get("$rb")).strip()
                if sender not in redial_lists:
                    KSR.sl.send_reply(403, "Not Registered")
                    return 1

                if body.startswith("ACTIVATE"):
                    # Limpeza de lista numa linha (remove sip:, adiciona domínio se faltar)
                    raw_targets = body.split()[1:]
                    clean = [f"sip:{u.replace('sip:','')}@{OPERATOR_DOMAIN}" if '@' not in u else f"sip:{u.replace('sip:','')}" for u in raw_targets]
                    
                    redial_lists[sender] = clean
                    KSR.sl.send_reply(200, f"Activated: {clean}")
                    return 1

                if body.startswith("DEACTIVATE"):
                    redial_lists[sender] = []
                    KSR.sl.send_reply(200, "Deactivated")
                    return 1
                
                KSR.sl.send_reply(400, "Unknown Command")
                return 1

        # 3. CHAMADAS (INVITE)
        if KSR.is_method("INVITE"):
            target = KSR.pv.get("$tu")
            watchlist = redial_lists.get(sender, [])

            # Lógica Redial
            if watchlist and target in watchlist:
                KSR.info(f"[REDIAL] Monitoring call to {target}\n")
                KSR.pv.sets("$avp(retries)", str(MAX_RETRIES))
                KSR.pv.sets("$avp(redial_targets)", ",".join(watchlist))
                KSR.pv.sets("$avp(current_idx)", "0")
                
                KSR.tm.t_on_failure("failure_REDIAL")
                KSR.tm.t_set_fr(TEST_TIMEOUT, TEST_TIMEOUT)

                if KSR.registrar.lookup("location") != 1:
                     return self.try_next_redial() # Destino offline, inicia redial

                KSR.tm.t_relay()
                return 1

            # Chamada Normal
            if KSR.registrar.lookup("location") == 1:
                KSR.tm.t_relay()
            else:
                KSR.sl.send_reply(404, "Not Found")
            return 1

        # 4. IN-DIALOG (ACK, BYE, ETC)
        if KSR.rr.loose_route():
            KSR.tm.t_relay()
        return 1

    # --- TRATAMENTO DE FALHAS ---
    def failure_REDIAL(self, msg):
        status = int(KSR.pv.get("$rs") or 0)
        # 0=Local Timeout/Err, 408=Timeout, 480=Unavailable, 486=Busy
        if status in [0, 408, 480, 486]:
            KSR.info(f"[FAIL] Status {status}. Redialing...\n")
            return self.try_next_redial()
        return 1